rule TTP_XOR_MULT_DOSStub_70b4 {
  strings:
    $key_70b4 = { 24 dc [2] 50 c4 [2] 17 c6 [2] 50 d7 [2] 1e db [2] 12 d1 [2] 05 da [2] 1e 94 [2] 23 }

  condition:
    any of them
}