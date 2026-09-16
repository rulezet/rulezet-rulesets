rule TTP_XOR_MULT_DOSStub_d1bb {
  strings:
    $key_d1bb = { 85 d3 [2] f1 cb [2] b6 c9 [2] f1 d8 [2] bf d4 [2] b3 de [2] a4 d5 [2] bf 9b [2] 82 }

  condition:
    any of them
}