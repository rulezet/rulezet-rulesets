rule TTP_XOR_MULT_DOSStub_28bb {
  strings:
    $key_28bb = { 7c d3 [2] 08 cb [2] 4f c9 [2] 08 d8 [2] 46 d4 [2] 4a de [2] 5d d5 [2] 46 9b [2] 7b }

  condition:
    any of them
}