rule TTP_XOR_MULT_DOSStub_55bb {
  strings:
    $key_55bb = { 01 d3 [2] 75 cb [2] 32 c9 [2] 75 d8 [2] 3b d4 [2] 37 de [2] 20 d5 [2] 3b 9b [2] 06 }

  condition:
    any of them
}