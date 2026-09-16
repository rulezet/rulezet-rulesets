rule TTP_XOR_MULT_DOSStub_8cc1 {
  strings:
    $key_8cc1 = { d8 a9 [2] ac b1 [2] eb b3 [2] ac a2 [2] e2 ae [2] ee a4 [2] f9 af [2] e2 e1 [2] df }

  condition:
    any of them
}