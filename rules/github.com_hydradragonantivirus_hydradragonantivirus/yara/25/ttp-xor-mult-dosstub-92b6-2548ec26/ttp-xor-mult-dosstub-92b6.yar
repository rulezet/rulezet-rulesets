rule TTP_XOR_MULT_DOSStub_92b6 {
  strings:
    $key_92b6 = { c6 de [2] b2 c6 [2] f5 c4 [2] b2 d5 [2] fc d9 [2] f0 d3 [2] e7 d8 [2] fc 96 [2] c1 }

  condition:
    any of them
}