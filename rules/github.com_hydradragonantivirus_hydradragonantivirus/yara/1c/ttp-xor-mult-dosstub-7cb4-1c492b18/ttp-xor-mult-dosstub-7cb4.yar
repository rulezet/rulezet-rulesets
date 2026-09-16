rule TTP_XOR_MULT_DOSStub_7cb4 {
  strings:
    $key_7cb4 = { 28 dc [2] 5c c4 [2] 1b c6 [2] 5c d7 [2] 12 db [2] 1e d1 [2] 09 da [2] 12 94 [2] 2f }

  condition:
    any of them
}