rule TTP_XOR_MULT_DOSStub_46b0 {
  strings:
    $key_46b0 = { 12 d8 [2] 66 c0 [2] 21 c2 [2] 66 d3 [2] 28 df [2] 24 d5 [2] 33 de [2] 28 90 [2] 15 }

  condition:
    any of them
}