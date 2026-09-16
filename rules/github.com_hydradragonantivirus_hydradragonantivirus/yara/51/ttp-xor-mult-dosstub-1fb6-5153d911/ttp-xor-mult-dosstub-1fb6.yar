rule TTP_XOR_MULT_DOSStub_1fb6 {
  strings:
    $key_1fb6 = { 4b de [2] 3f c6 [2] 78 c4 [2] 3f d5 [2] 71 d9 [2] 7d d3 [2] 6a d8 [2] 71 96 [2] 4c }

  condition:
    any of them
}