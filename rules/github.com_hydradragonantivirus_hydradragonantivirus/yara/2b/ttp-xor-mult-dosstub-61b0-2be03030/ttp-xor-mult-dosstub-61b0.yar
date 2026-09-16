rule TTP_XOR_MULT_DOSStub_61b0 {
  strings:
    $key_61b0 = { 35 d8 [2] 41 c0 [2] 06 c2 [2] 41 d3 [2] 0f df [2] 03 d5 [2] 14 de [2] 0f 90 [2] 32 }

  condition:
    any of them
}