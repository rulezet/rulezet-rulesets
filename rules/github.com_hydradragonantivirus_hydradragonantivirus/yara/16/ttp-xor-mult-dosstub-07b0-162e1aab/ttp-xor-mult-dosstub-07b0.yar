rule TTP_XOR_MULT_DOSStub_07b0 {
  strings:
    $key_07b0 = { 53 d8 [2] 27 c0 [2] 60 c2 [2] 27 d3 [2] 69 df [2] 65 d5 [2] 72 de [2] 69 90 [2] 54 }

  condition:
    any of them
}