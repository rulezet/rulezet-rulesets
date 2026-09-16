rule TTP_XOR_MULT_DOSStub_c6bb {
  strings:
    $key_c6bb = { 92 d3 [2] e6 cb [2] a1 c9 [2] e6 d8 [2] a8 d4 [2] a4 de [2] b3 d5 [2] a8 9b [2] 95 }

  condition:
    any of them
}