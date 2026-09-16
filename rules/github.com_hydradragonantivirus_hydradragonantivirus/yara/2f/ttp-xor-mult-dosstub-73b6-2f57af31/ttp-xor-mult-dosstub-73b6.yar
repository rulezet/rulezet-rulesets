rule TTP_XOR_MULT_DOSStub_73b6 {
  strings:
    $key_73b6 = { 27 de [2] 53 c6 [2] 14 c4 [2] 53 d5 [2] 1d d9 [2] 11 d3 [2] 06 d8 [2] 1d 96 [2] 20 }

  condition:
    any of them
}