rule TTP_XOR_MULT_DOSStub_63b0 {
  strings:
    $key_63b0 = { 37 d8 [2] 43 c0 [2] 04 c2 [2] 43 d3 [2] 0d df [2] 01 d5 [2] 16 de [2] 0d 90 [2] 30 }

  condition:
    any of them
}