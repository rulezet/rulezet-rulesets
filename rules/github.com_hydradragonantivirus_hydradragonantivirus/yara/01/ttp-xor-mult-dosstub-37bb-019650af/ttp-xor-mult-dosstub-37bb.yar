rule TTP_XOR_MULT_DOSStub_37bb {
  strings:
    $key_37bb = { 63 d3 [2] 17 cb [2] 50 c9 [2] 17 d8 [2] 59 d4 [2] 55 de [2] 42 d5 [2] 59 9b [2] 64 }

  condition:
    any of them
}