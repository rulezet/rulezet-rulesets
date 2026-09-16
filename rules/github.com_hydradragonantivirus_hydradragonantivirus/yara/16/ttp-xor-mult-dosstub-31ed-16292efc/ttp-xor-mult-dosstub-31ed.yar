rule TTP_XOR_MULT_DOSStub_31ed {
  strings:
    $key_31ed = { 65 85 [2] 11 9d [2] 56 9f [2] 11 8e [2] 5f 82 [2] 53 88 [2] 44 83 [2] 5f cd [2] 62 }

  condition:
    any of them
}