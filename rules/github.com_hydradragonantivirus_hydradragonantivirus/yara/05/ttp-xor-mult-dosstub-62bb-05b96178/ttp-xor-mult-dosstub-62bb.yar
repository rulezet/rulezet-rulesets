rule TTP_XOR_MULT_DOSStub_62bb {
  strings:
    $key_62bb = { 36 d3 [2] 42 cb [2] 05 c9 [2] 42 d8 [2] 0c d4 [2] 00 de [2] 17 d5 [2] 0c 9b [2] 31 }

  condition:
    any of them
}