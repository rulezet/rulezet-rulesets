rule TTP_XOR_MULT_DOSStub_66b0 {
  strings:
    $key_66b0 = { 32 d8 [2] 46 c0 [2] 01 c2 [2] 46 d3 [2] 08 df [2] 04 d5 [2] 13 de [2] 08 90 [2] 35 }

  condition:
    any of them
}