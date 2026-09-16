rule TTP_XOR_MULT_DOSStub_79bb {
  strings:
    $key_79bb = { 2d d3 [2] 59 cb [2] 1e c9 [2] 59 d8 [2] 17 d4 [2] 1b de [2] 0c d5 [2] 17 9b [2] 2a }

  condition:
    any of them
}