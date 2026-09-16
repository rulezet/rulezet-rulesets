rule TTP_XOR_MULT_DOSStub_8082 {
  strings:
    $key_8082 = { d4 ea [2] a0 f2 [2] e7 f0 [2] a0 e1 [2] ee ed [2] e2 e7 [2] f5 ec [2] ee a2 [2] d3 }

  condition:
    any of them
}