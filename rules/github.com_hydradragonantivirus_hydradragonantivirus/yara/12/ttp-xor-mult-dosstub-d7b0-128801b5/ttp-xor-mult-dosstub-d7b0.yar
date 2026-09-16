rule TTP_XOR_MULT_DOSStub_d7b0 {
  strings:
    $key_d7b0 = { 83 d8 [2] f7 c0 [2] b0 c2 [2] f7 d3 [2] b9 df [2] b5 d5 [2] a2 de [2] b9 90 [2] 84 }

  condition:
    any of them
}