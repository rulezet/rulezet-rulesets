rule TTP_XOR_MULT_DOSStub_3bb9 {
  strings:
    $key_3bb9 = { 6f d1 [2] 1b c9 [2] 5c cb [2] 1b da [2] 55 d6 [2] 59 dc [2] 4e d7 [2] 55 99 [2] 68 }

  condition:
    any of them
}