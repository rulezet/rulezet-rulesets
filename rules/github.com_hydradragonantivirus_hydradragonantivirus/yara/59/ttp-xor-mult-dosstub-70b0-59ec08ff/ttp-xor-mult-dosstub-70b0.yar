rule TTP_XOR_MULT_DOSStub_70b0 {
  strings:
    $key_70b0 = { 24 d8 [2] 50 c0 [2] 17 c2 [2] 50 d3 [2] 1e df [2] 12 d5 [2] 05 de [2] 1e 90 [2] 23 }

  condition:
    any of them
}