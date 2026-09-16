rule TTP_XOR_MULT_DOSStub_80c4 {
  strings:
    $key_80c4 = { d4 ac [2] a0 b4 [2] e7 b6 [2] a0 a7 [2] ee ab [2] e2 a1 [2] f5 aa [2] ee e4 [2] d3 }

  condition:
    any of them
}