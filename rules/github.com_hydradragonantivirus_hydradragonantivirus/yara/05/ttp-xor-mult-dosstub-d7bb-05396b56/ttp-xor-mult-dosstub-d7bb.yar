rule TTP_XOR_MULT_DOSStub_d7bb {
  strings:
    $key_d7bb = { 83 d3 [2] f7 cb [2] b0 c9 [2] f7 d8 [2] b9 d4 [2] b5 de [2] a2 d5 [2] b9 9b [2] 84 }

  condition:
    any of them
}