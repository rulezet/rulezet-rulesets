rule TTP_XOR_MULT_DOSStub_36b0 {
  strings:
    $key_36b0 = { 62 d8 [2] 16 c0 [2] 51 c2 [2] 16 d3 [2] 58 df [2] 54 d5 [2] 43 de [2] 58 90 [2] 65 }

  condition:
    any of them
}