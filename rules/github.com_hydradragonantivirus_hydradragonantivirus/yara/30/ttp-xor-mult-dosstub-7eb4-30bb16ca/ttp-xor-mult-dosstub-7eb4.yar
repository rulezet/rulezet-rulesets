rule TTP_XOR_MULT_DOSStub_7eb4 {
  strings:
    $key_7eb4 = { 2a dc [2] 5e c4 [2] 19 c6 [2] 5e d7 [2] 10 db [2] 1c d1 [2] 0b da [2] 10 94 [2] 2d }

  condition:
    any of them
}