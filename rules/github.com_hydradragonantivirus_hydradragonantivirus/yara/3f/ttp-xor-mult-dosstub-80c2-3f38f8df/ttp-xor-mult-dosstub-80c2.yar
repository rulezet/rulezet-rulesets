rule TTP_XOR_MULT_DOSStub_80c2 {
  strings:
    $key_80c2 = { d4 aa [2] a0 b2 [2] e7 b0 [2] a0 a1 [2] ee ad [2] e2 a7 [2] f5 ac [2] ee e2 [2] d3 }

  condition:
    any of them
}