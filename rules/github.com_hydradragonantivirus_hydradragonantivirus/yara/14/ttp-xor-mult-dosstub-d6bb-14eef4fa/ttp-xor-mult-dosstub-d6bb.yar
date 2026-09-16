rule TTP_XOR_MULT_DOSStub_d6bb {
  strings:
    $key_d6bb = { 82 d3 [2] f6 cb [2] b1 c9 [2] f6 d8 [2] b8 d4 [2] b4 de [2] a3 d5 [2] b8 9b [2] 85 }

  condition:
    any of them
}