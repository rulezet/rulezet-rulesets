rule TTP_XOR_MULT_DOSStub_09a6 {
  strings:
    $key_09a6 = { 5d ce [2] 29 d6 [2] 6e d4 [2] 29 c5 [2] 67 c9 [2] 6b c3 [2] 7c c8 [2] 67 86 [2] 5a }

  condition:
    any of them
}