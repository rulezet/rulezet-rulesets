rule TTP_XOR_MULT_DOSStub_c7bb {
  strings:
    $key_c7bb = { 93 d3 [2] e7 cb [2] a0 c9 [2] e7 d8 [2] a9 d4 [2] a5 de [2] b2 d5 [2] a9 9b [2] 94 }

  condition:
    any of them
}