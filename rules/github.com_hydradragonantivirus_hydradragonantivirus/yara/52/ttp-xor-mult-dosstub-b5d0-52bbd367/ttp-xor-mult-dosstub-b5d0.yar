rule TTP_XOR_MULT_DOSStub_b5d0 {
  strings:
    $key_b5d0 = { e1 b8 [2] 95 a0 [2] d2 a2 [2] 95 b3 [2] db bf [2] d7 b5 [2] c0 be [2] db f0 [2] e6 }

  condition:
    any of them
}