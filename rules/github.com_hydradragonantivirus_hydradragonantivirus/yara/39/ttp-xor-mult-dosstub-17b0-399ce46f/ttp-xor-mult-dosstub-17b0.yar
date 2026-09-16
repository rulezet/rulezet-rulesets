rule TTP_XOR_MULT_DOSStub_17b0 {
  strings:
    $key_17b0 = { 43 d8 [2] 37 c0 [2] 70 c2 [2] 37 d3 [2] 79 df [2] 75 d5 [2] 62 de [2] 79 90 [2] 44 }

  condition:
    any of them
}