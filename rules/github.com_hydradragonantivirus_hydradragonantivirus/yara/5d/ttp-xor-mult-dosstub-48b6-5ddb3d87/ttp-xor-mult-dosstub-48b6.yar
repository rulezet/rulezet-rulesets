rule TTP_XOR_MULT_DOSStub_48b6 {
  strings:
    $key_48b6 = { 1c de [2] 68 c6 [2] 2f c4 [2] 68 d5 [2] 26 d9 [2] 2a d3 [2] 3d d8 [2] 26 96 [2] 1b }

  condition:
    any of them
}