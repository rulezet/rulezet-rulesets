rule TTP_XOR_MULT_DOSStub_d4bb {
  strings:
    $key_d4bb = { 80 d3 [2] f4 cb [2] b3 c9 [2] f4 d8 [2] ba d4 [2] b6 de [2] a1 d5 [2] ba 9b [2] 87 }

  condition:
    any of them
}