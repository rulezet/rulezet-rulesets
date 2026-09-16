rule TTP_XOR_MULT_DOSStub_8083 {
  strings:
    $key_8083 = { d4 eb [2] a0 f3 [2] e7 f1 [2] a0 e0 [2] ee ec [2] e2 e6 [2] f5 ed [2] ee a3 [2] d3 }

  condition:
    any of them
}