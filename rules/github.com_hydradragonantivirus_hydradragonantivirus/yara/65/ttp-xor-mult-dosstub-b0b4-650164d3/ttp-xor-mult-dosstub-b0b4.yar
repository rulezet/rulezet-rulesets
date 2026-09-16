rule TTP_XOR_MULT_DOSStub_b0b4 {
  strings:
    $key_b0b4 = { e4 dc [2] 90 c4 [2] d7 c6 [2] 90 d7 [2] de db [2] d2 d1 [2] c5 da [2] de 94 [2] e3 }

  condition:
    any of them
}