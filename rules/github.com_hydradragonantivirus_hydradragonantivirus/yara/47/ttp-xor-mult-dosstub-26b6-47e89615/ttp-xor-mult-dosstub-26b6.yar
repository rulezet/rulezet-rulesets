rule TTP_XOR_MULT_DOSStub_26b6 {
  strings:
    $key_26b6 = { 72 de [2] 06 c6 [2] 41 c4 [2] 06 d5 [2] 48 d9 [2] 44 d3 [2] 53 d8 [2] 48 96 [2] 75 }

  condition:
    any of them
}