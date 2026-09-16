rule TTP_XOR_MULT_DOSStub_0cb5 {
  strings:
    $key_0cb5 = { 58 dd [2] 2c c5 [2] 6b c7 [2] 2c d6 [2] 62 da [2] 6e d0 [2] 79 db [2] 62 95 [2] 5f }

  condition:
    any of them
}