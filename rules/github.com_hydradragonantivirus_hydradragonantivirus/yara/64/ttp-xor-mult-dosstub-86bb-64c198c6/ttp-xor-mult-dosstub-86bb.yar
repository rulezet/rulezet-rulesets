rule TTP_XOR_MULT_DOSStub_86bb {
  strings:
    $key_86bb = { d2 d3 [2] a6 cb [2] e1 c9 [2] a6 d8 [2] e8 d4 [2] e4 de [2] f3 d5 [2] e8 9b [2] d5 }

  condition:
    any of them
}