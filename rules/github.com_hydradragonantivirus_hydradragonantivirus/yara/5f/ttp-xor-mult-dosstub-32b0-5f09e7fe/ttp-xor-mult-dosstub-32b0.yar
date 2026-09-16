rule TTP_XOR_MULT_DOSStub_32b0 {
  strings:
    $key_32b0 = { 66 d8 [2] 12 c0 [2] 55 c2 [2] 12 d3 [2] 5c df [2] 50 d5 [2] 47 de [2] 5c 90 [2] 61 }

  condition:
    any of them
}