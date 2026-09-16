rule TTP_XOR_MULT_DOSStub_95bb {
  strings:
    $key_95bb = { c1 d3 [2] b5 cb [2] f2 c9 [2] b5 d8 [2] fb d4 [2] f7 de [2] e0 d5 [2] fb 9b [2] c6 }

  condition:
    any of them
}