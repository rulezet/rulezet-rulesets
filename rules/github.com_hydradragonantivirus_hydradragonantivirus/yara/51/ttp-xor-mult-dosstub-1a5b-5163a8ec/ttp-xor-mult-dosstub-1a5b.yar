rule TTP_XOR_MULT_DOSStub_1a5b {
  strings:
    $key_1a5b = { 4e 33 [2] 3a 2b [2] 7d 29 [2] 3a 38 [2] 74 34 [2] 78 3e [2] 6f 35 [2] 74 7b [2] 49 }

  condition:
    any of them
}