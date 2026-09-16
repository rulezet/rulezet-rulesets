rule TTP_XOR_MULT_DOSStub_58bb {
  strings:
    $key_58bb = { 0c d3 [2] 78 cb [2] 3f c9 [2] 78 d8 [2] 36 d4 [2] 3a de [2] 2d d5 [2] 36 9b [2] 0b }

  condition:
    any of them
}