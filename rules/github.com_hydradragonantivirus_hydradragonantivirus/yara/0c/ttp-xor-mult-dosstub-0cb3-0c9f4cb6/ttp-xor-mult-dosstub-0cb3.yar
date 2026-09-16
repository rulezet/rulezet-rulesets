rule TTP_XOR_MULT_DOSStub_0cb3 {
  strings:
    $key_0cb3 = { 58 db [2] 2c c3 [2] 6b c1 [2] 2c d0 [2] 62 dc [2] 6e d6 [2] 79 dd [2] 62 93 [2] 5f }

  condition:
    any of them
}