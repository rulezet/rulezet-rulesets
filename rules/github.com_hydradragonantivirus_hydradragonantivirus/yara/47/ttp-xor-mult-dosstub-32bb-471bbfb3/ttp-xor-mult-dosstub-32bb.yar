rule TTP_XOR_MULT_DOSStub_32bb {
  strings:
    $key_32bb = { 66 d3 [2] 12 cb [2] 55 c9 [2] 12 d8 [2] 5c d4 [2] 50 de [2] 47 d5 [2] 5c 9b [2] 61 }

  condition:
    any of them
}