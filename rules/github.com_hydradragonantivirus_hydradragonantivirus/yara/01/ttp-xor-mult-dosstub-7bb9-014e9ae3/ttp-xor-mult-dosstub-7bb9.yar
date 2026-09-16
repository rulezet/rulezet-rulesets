rule TTP_XOR_MULT_DOSStub_7bb9 {
  strings:
    $key_7bb9 = { 2f d1 [2] 5b c9 [2] 1c cb [2] 5b da [2] 15 d6 [2] 19 dc [2] 0e d7 [2] 15 99 [2] 28 }

  condition:
    any of them
}