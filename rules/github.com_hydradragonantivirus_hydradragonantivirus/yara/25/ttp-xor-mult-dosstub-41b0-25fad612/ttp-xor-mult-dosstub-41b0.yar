rule TTP_XOR_MULT_DOSStub_41b0 {
  strings:
    $key_41b0 = { 15 d8 [2] 61 c0 [2] 26 c2 [2] 61 d3 [2] 2f df [2] 23 d5 [2] 34 de [2] 2f 90 [2] 12 }

  condition:
    any of them
}