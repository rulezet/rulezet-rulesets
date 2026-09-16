rule TTP_XOR_MULT_DOSStub_59a6 {
  strings:
    $key_59a6 = { 0d ce [2] 79 d6 [2] 3e d4 [2] 79 c5 [2] 37 c9 [2] 3b c3 [2] 2c c8 [2] 37 86 [2] 0a }

  condition:
    any of them
}