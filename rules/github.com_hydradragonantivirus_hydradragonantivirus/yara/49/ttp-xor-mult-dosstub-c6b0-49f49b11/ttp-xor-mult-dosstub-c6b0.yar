rule TTP_XOR_MULT_DOSStub_c6b0 {
  strings:
    $key_c6b0 = { 92 d8 [2] e6 c0 [2] a1 c2 [2] e6 d3 [2] a8 df [2] a4 d5 [2] b3 de [2] a8 90 [2] 95 }

  condition:
    any of them
}