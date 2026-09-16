rule TTP_XOR_MULT_DOSStub_40bb {
  strings:
    $key_40bb = { 14 d3 [2] 60 cb [2] 27 c9 [2] 60 d8 [2] 2e d4 [2] 22 de [2] 35 d5 [2] 2e 9b [2] 13 }

  condition:
    any of them
}