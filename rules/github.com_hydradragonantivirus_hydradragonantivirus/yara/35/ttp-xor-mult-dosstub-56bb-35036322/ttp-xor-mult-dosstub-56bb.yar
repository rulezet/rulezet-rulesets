rule TTP_XOR_MULT_DOSStub_56bb {
  strings:
    $key_56bb = { 02 d3 [2] 76 cb [2] 31 c9 [2] 76 d8 [2] 38 d4 [2] 34 de [2] 23 d5 [2] 38 9b [2] 05 }

  condition:
    any of them
}