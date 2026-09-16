rule TTP_XOR_MULT_DOSStub_92bb {
  strings:
    $key_92bb = { c6 d3 [2] b2 cb [2] f5 c9 [2] b2 d8 [2] fc d4 [2] f0 de [2] e7 d5 [2] fc 9b [2] c1 }

  condition:
    any of them
}