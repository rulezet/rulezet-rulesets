rule TTP_XOR_MULT_DOSStub_07bb {
  strings:
    $key_07bb = { 53 d3 [2] 27 cb [2] 60 c9 [2] 27 d8 [2] 69 d4 [2] 65 de [2] 72 d5 [2] 69 9b [2] 54 }

  condition:
    any of them
}