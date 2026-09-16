rule TTP_XOR_MULT_DOSStub_9bcb {
  strings:
    $key_9bcb = { cf a3 [2] bb bb [2] fc b9 [2] bb a8 [2] f5 a4 [2] f9 ae [2] ee a5 [2] f5 eb [2] c8 }

  condition:
    any of them
}