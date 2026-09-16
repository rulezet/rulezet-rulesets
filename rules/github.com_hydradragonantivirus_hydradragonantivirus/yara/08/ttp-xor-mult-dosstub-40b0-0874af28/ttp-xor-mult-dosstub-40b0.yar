rule TTP_XOR_MULT_DOSStub_40b0 {
  strings:
    $key_40b0 = { 14 d8 [2] 60 c0 [2] 27 c2 [2] 60 d3 [2] 2e df [2] 22 d5 [2] 35 de [2] 2e 90 [2] 13 }

  condition:
    any of them
}