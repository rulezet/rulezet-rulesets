rule TTP_XOR_MULT_DOSStub_85bb {
  strings:
    $key_85bb = { d1 d3 [2] a5 cb [2] e2 c9 [2] a5 d8 [2] eb d4 [2] e7 de [2] f0 d5 [2] eb 9b [2] d6 }

  condition:
    any of them
}