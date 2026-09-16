rule TTP_XOR_MULT_DOSStub_80c0 {
  strings:
    $key_80c0 = { d4 a8 [2] a0 b0 [2] e7 b2 [2] a0 a3 [2] ee af [2] e2 a5 [2] f5 ae [2] ee e0 [2] d3 }

  condition:
    any of them
}