rule TTP_XOR_MULT_DOSStub_70b2 {
  strings:
    $key_70b2 = { 24 da [2] 50 c2 [2] 17 c0 [2] 50 d1 [2] 1e dd [2] 12 d7 [2] 05 dc [2] 1e 92 [2] 23 }

  condition:
    any of them
}