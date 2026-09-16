rule TTP_XOR_MULT_DOSStub_b0b2 {
  strings:
    $key_b0b2 = { e4 da [2] 90 c2 [2] d7 c0 [2] 90 d1 [2] de dd [2] d2 d7 [2] c5 dc [2] de 92 [2] e3 }

  condition:
    any of them
}