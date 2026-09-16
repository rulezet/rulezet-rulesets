rule TTP_XOR_MULT_DOSStub_c4b0 {
  strings:
    $key_c4b0 = { 90 d8 [2] e4 c0 [2] a3 c2 [2] e4 d3 [2] aa df [2] a6 d5 [2] b1 de [2] aa 90 [2] 97 }

  condition:
    any of them
}