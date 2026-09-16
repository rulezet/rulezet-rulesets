rule TTP_XOR_MULT_DOSStub_52bb {
  strings:
    $key_52bb = { 06 d3 [2] 72 cb [2] 35 c9 [2] 72 d8 [2] 3c d4 [2] 30 de [2] 27 d5 [2] 3c 9b [2] 01 }

  condition:
    any of them
}