rule TTP_XOR_MULT_DOSStub_96b6 {
  strings:
    $key_96b6 = { c2 de [2] b6 c6 [2] f1 c4 [2] b6 d5 [2] f8 d9 [2] f4 d3 [2] e3 d8 [2] f8 96 [2] c5 }

  condition:
    any of them
}