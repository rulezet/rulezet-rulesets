rule TTP_XOR_MULT_DOSStub_b3bb {
  strings:
    $key_b3bb = { e7 d3 [2] 93 cb [2] d4 c9 [2] 93 d8 [2] dd d4 [2] d1 de [2] c6 d5 [2] dd 9b [2] e0 }

  condition:
    any of them
}