rule TTP_XOR_MULT_DOSStub_94b6 {
  strings:
    $key_94b6 = { c0 de [2] b4 c6 [2] f3 c4 [2] b4 d5 [2] fa d9 [2] f6 d3 [2] e1 d8 [2] fa 96 [2] c7 }

  condition:
    any of them
}