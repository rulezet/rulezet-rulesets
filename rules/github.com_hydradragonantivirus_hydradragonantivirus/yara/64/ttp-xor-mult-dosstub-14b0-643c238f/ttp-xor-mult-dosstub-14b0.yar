rule TTP_XOR_MULT_DOSStub_14b0 {
  strings:
    $key_14b0 = { 40 d8 [2] 34 c0 [2] 73 c2 [2] 34 d3 [2] 7a df [2] 76 d5 [2] 61 de [2] 7a 90 [2] 47 }

  condition:
    any of them
}