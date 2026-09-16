rule TTP_XOR_MULT_DOSStub_5bb9 {
  strings:
    $key_5bb9 = { 0f d1 [2] 7b c9 [2] 3c cb [2] 7b da [2] 35 d6 [2] 39 dc [2] 2e d7 [2] 35 99 [2] 08 }

  condition:
    any of them
}