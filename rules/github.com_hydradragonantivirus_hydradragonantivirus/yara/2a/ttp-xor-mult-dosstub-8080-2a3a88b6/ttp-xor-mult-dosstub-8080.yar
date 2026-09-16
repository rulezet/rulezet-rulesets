rule TTP_XOR_MULT_DOSStub_8080 {
  strings:
    $key_8080 = { d4 e8 [2] a0 f0 [2] e7 f2 [2] a0 e3 [2] ee ef [2] e2 e5 [2] f5 ee [2] ee a0 [2] d3 }

  condition:
    any of them
}