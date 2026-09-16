rule TTP_XOR_MULT_DOSStub_05ed {
  strings:
    $key_05ed = { 51 85 [2] 25 9d [2] 62 9f [2] 25 8e [2] 6b 82 [2] 67 88 [2] 70 83 [2] 6b cd [2] 56 }

  condition:
    any of them
}