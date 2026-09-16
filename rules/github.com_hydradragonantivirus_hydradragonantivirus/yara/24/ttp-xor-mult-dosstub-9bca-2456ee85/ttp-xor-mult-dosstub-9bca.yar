rule TTP_XOR_MULT_DOSStub_9bca {
  strings:
    $key_9bca = { cf a2 [2] bb ba [2] fc b8 [2] bb a9 [2] f5 a5 [2] f9 af [2] ee a4 [2] f5 ea [2] c8 }

  condition:
    any of them
}