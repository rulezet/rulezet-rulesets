rule TTP_XOR_MULT_DOSStub_2eb4 {
  strings:
    $key_2eb4 = { 7a dc [2] 0e c4 [2] 49 c6 [2] 0e d7 [2] 40 db [2] 4c d1 [2] 5b da [2] 40 94 [2] 7d }

  condition:
    any of them
}