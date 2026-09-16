rule TTP_XOR_MULT_DOSStub_04b0 {
  strings:
    $key_04b0 = { 50 d8 [2] 24 c0 [2] 63 c2 [2] 24 d3 [2] 6a df [2] 66 d5 [2] 71 de [2] 6a 90 [2] 57 }

  condition:
    any of them
}