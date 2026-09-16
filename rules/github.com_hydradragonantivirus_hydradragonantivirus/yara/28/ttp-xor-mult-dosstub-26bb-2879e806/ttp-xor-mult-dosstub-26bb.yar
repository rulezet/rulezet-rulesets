rule TTP_XOR_MULT_DOSStub_26bb {
  strings:
    $key_26bb = { 72 d3 [2] 06 cb [2] 41 c9 [2] 06 d8 [2] 48 d4 [2] 44 de [2] 53 d5 [2] 48 9b [2] 75 }

  condition:
    any of them
}