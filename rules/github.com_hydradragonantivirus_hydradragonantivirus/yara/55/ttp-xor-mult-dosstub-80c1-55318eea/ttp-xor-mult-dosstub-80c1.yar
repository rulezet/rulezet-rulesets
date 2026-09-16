rule TTP_XOR_MULT_DOSStub_80c1 {
  strings:
    $key_80c1 = { d4 a9 [2] a0 b1 [2] e7 b3 [2] a0 a2 [2] ee ae [2] e2 a4 [2] f5 af [2] ee e1 [2] d3 }

  condition:
    any of them
}