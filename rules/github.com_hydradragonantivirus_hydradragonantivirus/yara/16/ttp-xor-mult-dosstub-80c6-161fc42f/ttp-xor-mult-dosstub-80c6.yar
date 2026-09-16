rule TTP_XOR_MULT_DOSStub_80c6 {
  strings:
    $key_80c6 = { d4 ae [2] a0 b6 [2] e7 b4 [2] a0 a5 [2] ee a9 [2] e2 a3 [2] f5 a8 [2] ee e6 [2] d3 }

  condition:
    any of them
}