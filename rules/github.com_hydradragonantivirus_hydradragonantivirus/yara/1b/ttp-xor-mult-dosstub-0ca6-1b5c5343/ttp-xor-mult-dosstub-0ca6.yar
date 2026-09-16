rule TTP_XOR_MULT_DOSStub_0ca6 {
  strings:
    $key_0ca6 = { 58 ce [2] 2c d6 [2] 6b d4 [2] 2c c5 [2] 62 c9 [2] 6e c3 [2] 79 c8 [2] 62 86 [2] 5f }

  condition:
    any of them
}