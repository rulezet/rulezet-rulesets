rule TTP_XOR_MULT_DOSStub_16bb {
  strings:
    $key_16bb = { 42 d3 [2] 36 cb [2] 71 c9 [2] 36 d8 [2] 78 d4 [2] 74 de [2] 63 d5 [2] 78 9b [2] 45 }

  condition:
    any of them
}