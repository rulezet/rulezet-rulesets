rule TTP_XOR_MULT_DOSStub_65bb {
  strings:
    $key_65bb = { 31 d3 [2] 45 cb [2] 02 c9 [2] 45 d8 [2] 0b d4 [2] 07 de [2] 10 d5 [2] 0b 9b [2] 36 }

  condition:
    any of them
}