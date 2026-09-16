rule TTP_XOR_MULT_DOSStub_97b6 {
  strings:
    $key_97b6 = { c3 de [2] b7 c6 [2] f0 c4 [2] b7 d5 [2] f9 d9 [2] f5 d3 [2] e2 d8 [2] f9 96 [2] c4 }

  condition:
    any of them
}