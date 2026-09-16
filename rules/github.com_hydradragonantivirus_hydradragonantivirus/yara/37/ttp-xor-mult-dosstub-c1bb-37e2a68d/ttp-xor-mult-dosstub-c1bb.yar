rule TTP_XOR_MULT_DOSStub_c1bb {
  strings:
    $key_c1bb = { 95 d3 [2] e1 cb [2] a6 c9 [2] e1 d8 [2] af d4 [2] a3 de [2] b4 d5 [2] af 9b [2] 92 }

  condition:
    any of them
}