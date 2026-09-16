rule TTP_XOR_MULT_DOSStub_b3b0 {
  strings:
    $key_b3b0 = { e7 d8 [2] 93 c0 [2] d4 c2 [2] 93 d3 [2] dd df [2] d1 d5 [2] c6 de [2] dd 90 [2] e0 }

  condition:
    any of them
}