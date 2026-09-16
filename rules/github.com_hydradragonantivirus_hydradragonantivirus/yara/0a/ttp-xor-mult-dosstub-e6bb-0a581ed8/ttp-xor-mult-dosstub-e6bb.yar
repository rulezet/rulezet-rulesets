rule TTP_XOR_MULT_DOSStub_e6bb {
  strings:
    $key_e6bb = { b2 d3 [2] c6 cb [2] 81 c9 [2] c6 d8 [2] 88 d4 [2] 84 de [2] 93 d5 [2] 88 9b [2] b5 }

  condition:
    any of them
}