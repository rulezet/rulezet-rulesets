rule TTP_XOR_MULT_DOSStub_8cc0 {
  strings:
    $key_8cc0 = { d8 a8 [2] ac b0 [2] eb b2 [2] ac a3 [2] e2 af [2] ee a5 [2] f9 ae [2] e2 e0 [2] df }

  condition:
    any of them
}