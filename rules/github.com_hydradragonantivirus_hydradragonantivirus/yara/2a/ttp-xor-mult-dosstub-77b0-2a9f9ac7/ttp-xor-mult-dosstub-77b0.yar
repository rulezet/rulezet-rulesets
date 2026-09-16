rule TTP_XOR_MULT_DOSStub_77b0 {
  strings:
    $key_77b0 = { 23 d8 [2] 57 c0 [2] 10 c2 [2] 57 d3 [2] 19 df [2] 15 d5 [2] 02 de [2] 19 90 [2] 24 }

  condition:
    any of them
}