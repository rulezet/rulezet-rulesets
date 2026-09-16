rule TTP_XOR_MULT_DOSStub_47bb {
  strings:
    $key_47bb = { 13 d3 [2] 67 cb [2] 20 c9 [2] 67 d8 [2] 29 d4 [2] 25 de [2] 32 d5 [2] 29 9b [2] 14 }

  condition:
    any of them
}