rule TTP_XOR_MULT_DOSStub_31bb {
  strings:
    $key_31bb = { 65 d3 [2] 11 cb [2] 56 c9 [2] 11 d8 [2] 5f d4 [2] 53 de [2] 44 d5 [2] 5f 9b [2] 62 }

  condition:
    any of them
}