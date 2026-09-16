rule TTP_XOR_MULT_DOSStub_41bb {
  strings:
    $key_41bb = { 15 d3 [2] 61 cb [2] 26 c9 [2] 61 d8 [2] 2f d4 [2] 23 de [2] 34 d5 [2] 2f 9b [2] 12 }

  condition:
    any of them
}