rule TTP_XOR_MULT_DOSStub_9bcc {
  strings:
    $key_9bcc = { cf a4 [2] bb bc [2] fc be [2] bb af [2] f5 a3 [2] f9 a9 [2] ee a2 [2] f5 ec [2] c8 }

  condition:
    any of them
}