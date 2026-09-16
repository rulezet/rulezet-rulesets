rule TTP_XOR_MULT_DOSStub_0bb9 {
  strings:
    $key_0bb9 = { 5f d1 [2] 2b c9 [2] 6c cb [2] 2b da [2] 65 d6 [2] 69 dc [2] 7e d7 [2] 65 99 [2] 58 }

  condition:
    any of them
}