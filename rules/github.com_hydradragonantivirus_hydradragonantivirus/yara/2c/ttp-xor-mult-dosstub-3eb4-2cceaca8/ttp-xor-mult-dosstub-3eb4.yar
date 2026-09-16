rule TTP_XOR_MULT_DOSStub_3eb4 {
  strings:
    $key_3eb4 = { 6a dc [2] 1e c4 [2] 59 c6 [2] 1e d7 [2] 50 db [2] 5c d1 [2] 4b da [2] 50 94 [2] 6d }

  condition:
    any of them
}