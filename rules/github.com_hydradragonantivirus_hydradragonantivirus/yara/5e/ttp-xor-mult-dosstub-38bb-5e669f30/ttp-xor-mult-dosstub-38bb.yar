rule TTP_XOR_MULT_DOSStub_38bb {
  strings:
    $key_38bb = { 6c d3 [2] 18 cb [2] 5f c9 [2] 18 d8 [2] 56 d4 [2] 5a de [2] 4d d5 [2] 56 9b [2] 6b }

  condition:
    any of them
}