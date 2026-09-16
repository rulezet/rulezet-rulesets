rule TTP_XOR_MULT_DOSStub_80cb {
  strings:
    $key_80cb = { d4 a3 [2] a0 bb [2] e7 b9 [2] a0 a8 [2] ee a4 [2] e2 ae [2] f5 a5 [2] ee eb [2] d3 }

  condition:
    any of them
}