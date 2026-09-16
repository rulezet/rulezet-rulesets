rule TTP_XOR_MULT_DOSStub_97bb {
  strings:
    $key_97bb = { c3 d3 [2] b7 cb [2] f0 c9 [2] b7 d8 [2] f9 d4 [2] f5 de [2] e2 d5 [2] f9 9b [2] c4 }

  condition:
    any of them
}