rule TTP_XOR_MULT_DOSStub_0cb4 {
  strings:
    $key_0cb4 = { 58 dc [2] 2c c4 [2] 6b c6 [2] 2c d7 [2] 62 db [2] 6e d1 [2] 79 da [2] 62 94 [2] 5f }

  condition:
    any of them
}