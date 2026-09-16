rule TTP_XOR_MULT_DOSStub_48bb {
  strings:
    $key_48bb = { 1c d3 [2] 68 cb [2] 2f c9 [2] 68 d8 [2] 26 d4 [2] 2a de [2] 3d d5 [2] 26 9b [2] 1b }

  condition:
    any of them
}