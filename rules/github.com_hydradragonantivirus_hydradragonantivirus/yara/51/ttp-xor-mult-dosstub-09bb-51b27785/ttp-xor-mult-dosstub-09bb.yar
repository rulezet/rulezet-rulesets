rule TTP_XOR_MULT_DOSStub_09bb {
  strings:
    $key_09bb = { 5d d3 [2] 29 cb [2] 6e c9 [2] 29 d8 [2] 67 d4 [2] 6b de [2] 7c d5 [2] 67 9b [2] 5a }

  condition:
    any of them
}