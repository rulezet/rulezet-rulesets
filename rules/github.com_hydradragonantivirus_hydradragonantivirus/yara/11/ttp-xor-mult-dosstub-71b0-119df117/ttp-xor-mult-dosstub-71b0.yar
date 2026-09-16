rule TTP_XOR_MULT_DOSStub_71b0 {
  strings:
    $key_71b0 = { 25 d8 [2] 51 c0 [2] 16 c2 [2] 51 d3 [2] 1f df [2] 13 d5 [2] 04 de [2] 1f 90 [2] 22 }

  condition:
    any of them
}