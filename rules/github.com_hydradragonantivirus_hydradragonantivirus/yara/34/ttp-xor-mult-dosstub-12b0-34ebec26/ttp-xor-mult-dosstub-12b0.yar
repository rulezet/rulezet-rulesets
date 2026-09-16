rule TTP_XOR_MULT_DOSStub_12b0 {
  strings:
    $key_12b0 = { 46 d8 [2] 32 c0 [2] 75 c2 [2] 32 d3 [2] 7c df [2] 70 d5 [2] 67 de [2] 7c 90 [2] 41 }

  condition:
    any of them
}