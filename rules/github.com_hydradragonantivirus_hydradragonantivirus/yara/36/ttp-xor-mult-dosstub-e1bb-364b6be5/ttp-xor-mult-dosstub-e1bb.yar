rule TTP_XOR_MULT_DOSStub_e1bb {
  strings:
    $key_e1bb = { b5 d3 [2] c1 cb [2] 86 c9 [2] c1 d8 [2] 8f d4 [2] 83 de [2] 94 d5 [2] 8f 9b [2] b2 }

  condition:
    any of them
}