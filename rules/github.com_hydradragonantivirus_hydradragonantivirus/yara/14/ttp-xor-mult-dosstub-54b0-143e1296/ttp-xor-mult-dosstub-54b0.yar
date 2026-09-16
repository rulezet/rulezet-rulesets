rule TTP_XOR_MULT_DOSStub_54b0 {
  strings:
    $key_54b0 = { 00 d8 [2] 74 c0 [2] 33 c2 [2] 74 d3 [2] 3a df [2] 36 d5 [2] 21 de [2] 3a 90 [2] 07 }

  condition:
    any of them
}