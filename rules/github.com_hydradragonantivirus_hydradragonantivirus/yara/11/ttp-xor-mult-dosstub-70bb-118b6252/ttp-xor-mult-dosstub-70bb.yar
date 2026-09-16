rule TTP_XOR_MULT_DOSStub_70bb {
  strings:
    $key_70bb = { 24 d3 [2] 50 cb [2] 17 c9 [2] 50 d8 [2] 1e d4 [2] 12 de [2] 05 d5 [2] 1e 9b [2] 23 }

  condition:
    any of them
}