rule TTP_XOR_MULT_DOSStub_18bb {
  strings:
    $key_18bb = { 4c d3 [2] 38 cb [2] 7f c9 [2] 38 d8 [2] 76 d4 [2] 7a de [2] 6d d5 [2] 76 9b [2] 4b }

  condition:
    any of them
}