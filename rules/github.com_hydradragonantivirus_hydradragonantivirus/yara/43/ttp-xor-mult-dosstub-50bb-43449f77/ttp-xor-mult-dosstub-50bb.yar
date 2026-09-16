rule TTP_XOR_MULT_DOSStub_50bb {
  strings:
    $key_50bb = { 04 d3 [2] 70 cb [2] 37 c9 [2] 70 d8 [2] 3e d4 [2] 32 de [2] 25 d5 [2] 3e 9b [2] 03 }

  condition:
    any of them
}