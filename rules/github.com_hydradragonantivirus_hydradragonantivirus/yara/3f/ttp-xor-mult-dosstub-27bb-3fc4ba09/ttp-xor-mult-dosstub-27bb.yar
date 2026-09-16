rule TTP_XOR_MULT_DOSStub_27bb {
  strings:
    $key_27bb = { 73 d3 [2] 07 cb [2] 40 c9 [2] 07 d8 [2] 49 d4 [2] 45 de [2] 52 d5 [2] 49 9b [2] 74 }

  condition:
    any of them
}