rule TTP_XOR_MULT_DOSStub_2bb9 {
  strings:
    $key_2bb9 = { 7f d1 [2] 0b c9 [2] 4c cb [2] 0b da [2] 45 d6 [2] 49 dc [2] 5e d7 [2] 45 99 [2] 78 }

  condition:
    any of them
}