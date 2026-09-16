rule TTP_XOR_MULT_DOSStub_78bb {
  strings:
    $key_78bb = { 2c d3 [2] 58 cb [2] 1f c9 [2] 58 d8 [2] 16 d4 [2] 1a de [2] 0d d5 [2] 16 9b [2] 2b }

  condition:
    any of them
}