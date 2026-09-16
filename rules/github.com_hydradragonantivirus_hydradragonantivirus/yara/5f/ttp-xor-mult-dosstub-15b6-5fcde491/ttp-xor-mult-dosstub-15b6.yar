rule TTP_XOR_MULT_DOSStub_15b6 {
  strings:
    $key_15b6 = { 41 de [2] 35 c6 [2] 72 c4 [2] 35 d5 [2] 7b d9 [2] 77 d3 [2] 60 d8 [2] 7b 96 [2] 46 }

  condition:
    any of them
}