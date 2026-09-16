rule TTP_XOR_MULT_DOSStub_c7b0 {
  strings:
    $key_c7b0 = { 93 d8 [2] e7 c0 [2] a0 c2 [2] e7 d3 [2] a9 df [2] a5 d5 [2] b2 de [2] a9 90 [2] 94 }

  condition:
    any of them
}