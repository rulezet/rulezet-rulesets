rule TTP_XOR_MULT_DOSStub_95b6 {
  strings:
    $key_95b6 = { c1 de [2] b5 c6 [2] f2 c4 [2] b5 d5 [2] fb d9 [2] f7 d3 [2] e0 d8 [2] fb 96 [2] c6 }

  condition:
    any of them
}