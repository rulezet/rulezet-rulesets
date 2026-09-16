rule TTP_XOR_MULT_DOSStub_05b0 {
  strings:
    $key_05b0 = { 51 d8 [2] 25 c0 [2] 62 c2 [2] 25 d3 [2] 6b df [2] 67 d5 [2] 70 de [2] 6b 90 [2] 56 }

  condition:
    any of them
}