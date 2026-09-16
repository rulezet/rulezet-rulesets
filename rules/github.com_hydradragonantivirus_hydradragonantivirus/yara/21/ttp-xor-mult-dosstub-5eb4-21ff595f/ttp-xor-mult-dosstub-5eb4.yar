rule TTP_XOR_MULT_DOSStub_5eb4 {
  strings:
    $key_5eb4 = { 0a dc [2] 7e c4 [2] 39 c6 [2] 7e d7 [2] 30 db [2] 3c d1 [2] 2b da [2] 30 94 [2] 0d }

  condition:
    any of them
}