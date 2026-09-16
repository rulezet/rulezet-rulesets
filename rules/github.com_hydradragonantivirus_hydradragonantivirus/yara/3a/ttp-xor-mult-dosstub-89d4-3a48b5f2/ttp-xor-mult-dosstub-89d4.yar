rule TTP_XOR_MULT_DOSStub_89d4 {
  strings:
    $key_89d4 = { dd bc [2] a9 a4 [2] ee a6 [2] a9 b7 [2] e7 bb [2] eb b1 [2] fc ba [2] e7 f4 [2] da }

  condition:
    any of them
}