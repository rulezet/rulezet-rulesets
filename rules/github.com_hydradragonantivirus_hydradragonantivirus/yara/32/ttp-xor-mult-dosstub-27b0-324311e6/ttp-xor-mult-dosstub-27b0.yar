rule TTP_XOR_MULT_DOSStub_27b0 {
  strings:
    $key_27b0 = { 73 d8 [2] 07 c0 [2] 40 c2 [2] 07 d3 [2] 49 df [2] 45 d5 [2] 52 de [2] 49 90 [2] 74 }

  condition:
    any of them
}