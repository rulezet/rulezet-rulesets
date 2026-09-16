rule TTP_XOR_MULT_DOSStub_3a5b {
  strings:
    $key_3a5b = { 6e 33 [2] 1a 2b [2] 5d 29 [2] 1a 38 [2] 54 34 [2] 58 3e [2] 4f 35 [2] 54 7b [2] 69 }

  condition:
    any of them
}