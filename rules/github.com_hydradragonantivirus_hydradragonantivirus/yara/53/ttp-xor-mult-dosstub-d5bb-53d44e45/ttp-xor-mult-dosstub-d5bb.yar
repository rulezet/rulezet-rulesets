rule TTP_XOR_MULT_DOSStub_d5bb {
  strings:
    $key_d5bb = { 81 d3 [2] f5 cb [2] b2 c9 [2] f5 d8 [2] bb d4 [2] b7 de [2] a0 d5 [2] bb 9b [2] 86 }

  condition:
    any of them
}