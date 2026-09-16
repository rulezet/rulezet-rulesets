rule TTP_XOR_MULT_DOSStub_35ed {
  strings:
    $key_35ed = { 61 85 [2] 15 9d [2] 52 9f [2] 15 8e [2] 5b 82 [2] 57 88 [2] 40 83 [2] 5b cd [2] 66 }

  condition:
    any of them
}