rule TTP_XOR_MULT_DOSStub_72bb {
  strings:
    $key_72bb = { 26 d3 [2] 52 cb [2] 15 c9 [2] 52 d8 [2] 1c d4 [2] 10 de [2] 07 d5 [2] 1c 9b [2] 21 }

  condition:
    any of them
}