rule TTP_XOR_MULT_DOSStub_8cc2 {
  strings:
    $key_8cc2 = { d8 aa [2] ac b2 [2] eb b0 [2] ac a1 [2] e2 ad [2] ee a7 [2] f9 ac [2] e2 e2 [2] df }

  condition:
    any of them
}