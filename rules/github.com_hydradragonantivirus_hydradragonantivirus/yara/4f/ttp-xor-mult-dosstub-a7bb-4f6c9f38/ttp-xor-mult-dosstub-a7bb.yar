rule TTP_XOR_MULT_DOSStub_a7bb {
  strings:
    $key_a7bb = { f3 d3 [2] 87 cb [2] c0 c9 [2] 87 d8 [2] c9 d4 [2] c5 de [2] d2 d5 [2] c9 9b [2] f4 }

  condition:
    any of them
}