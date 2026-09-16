rule TTP_XOR_MULT_DOSStub_d6b0 {
  strings:
    $key_d6b0 = { 82 d8 [2] f6 c0 [2] b1 c2 [2] f6 d3 [2] b8 df [2] b4 d5 [2] a3 de [2] b8 90 [2] 85 }

  condition:
    any of them
}