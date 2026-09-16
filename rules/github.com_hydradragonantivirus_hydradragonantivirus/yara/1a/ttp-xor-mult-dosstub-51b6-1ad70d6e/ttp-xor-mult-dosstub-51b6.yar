rule TTP_XOR_MULT_DOSStub_51b6 {
  strings:
    $key_51b6 = { 05 de [2] 71 c6 [2] 36 c4 [2] 71 d5 [2] 3f d9 [2] 33 d3 [2] 24 d8 [2] 3f 96 [2] 02 }

  condition:
    any of them
}