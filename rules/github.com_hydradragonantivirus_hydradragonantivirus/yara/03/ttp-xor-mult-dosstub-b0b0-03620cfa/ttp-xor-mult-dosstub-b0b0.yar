rule TTP_XOR_MULT_DOSStub_b0b0 {
  strings:
    $key_b0b0 = { e4 d8 [2] 90 c0 [2] d7 c2 [2] 90 d3 [2] de df [2] d2 d5 [2] c5 de [2] de 90 [2] e3 }

  condition:
    any of them
}