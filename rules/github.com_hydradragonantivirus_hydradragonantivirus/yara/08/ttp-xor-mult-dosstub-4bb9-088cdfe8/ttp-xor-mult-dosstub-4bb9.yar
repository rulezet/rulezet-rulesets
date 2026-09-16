rule TTP_XOR_MULT_DOSStub_4bb9 {
  strings:
    $key_4bb9 = { 1f d1 [2] 6b c9 [2] 2c cb [2] 6b da [2] 25 d6 [2] 29 dc [2] 3e d7 [2] 25 99 [2] 18 }

  condition:
    any of them
}