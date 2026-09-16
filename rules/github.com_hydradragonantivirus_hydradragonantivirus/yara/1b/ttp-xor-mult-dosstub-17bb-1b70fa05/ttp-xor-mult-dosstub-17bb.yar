rule TTP_XOR_MULT_DOSStub_17bb {
  strings:
    $key_17bb = { 43 d3 [2] 37 cb [2] 70 c9 [2] 37 d8 [2] 79 d4 [2] 75 de [2] 62 d5 [2] 79 9b [2] 44 }

  condition:
    any of them
}