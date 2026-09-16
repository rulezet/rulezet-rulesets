rule TTP_XOR_MULT_DOSStub_1a4b {
  strings:
    $key_1a4b = { 4e 23 [2] 3a 3b [2] 7d 39 [2] 3a 28 [2] 74 24 [2] 78 2e [2] 6f 25 [2] 74 6b [2] 49 }

  condition:
    any of them
}