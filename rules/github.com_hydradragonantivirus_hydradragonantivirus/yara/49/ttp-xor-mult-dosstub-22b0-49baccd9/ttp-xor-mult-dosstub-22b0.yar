rule TTP_XOR_MULT_DOSStub_22b0 {
  strings:
    $key_22b0 = { 76 d8 [2] 02 c0 [2] 45 c2 [2] 02 d3 [2] 4c df [2] 40 d5 [2] 57 de [2] 4c 90 [2] 71 }

  condition:
    any of them
}