rule TTP_XOR_MULT_DOSStub_74bb {
  strings:
    $key_74bb = { 20 d3 [2] 54 cb [2] 13 c9 [2] 54 d8 [2] 1a d4 [2] 16 de [2] 01 d5 [2] 1a 9b [2] 27 }

  condition:
    any of them
}