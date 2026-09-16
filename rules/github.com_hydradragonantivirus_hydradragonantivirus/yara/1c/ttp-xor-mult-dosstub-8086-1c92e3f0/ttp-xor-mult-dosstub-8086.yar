rule TTP_XOR_MULT_DOSStub_8086 {
  strings:
    $key_8086 = { d4 ee [2] a0 f6 [2] e7 f4 [2] a0 e5 [2] ee e9 [2] e2 e3 [2] f5 e8 [2] ee a6 [2] d3 }

  condition:
    any of them
}