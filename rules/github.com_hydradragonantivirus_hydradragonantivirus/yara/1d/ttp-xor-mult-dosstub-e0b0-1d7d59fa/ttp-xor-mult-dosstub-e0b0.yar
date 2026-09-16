rule TTP_XOR_MULT_DOSStub_e0b0 {
  strings:
    $key_e0b0 = { b4 d8 [2] c0 c0 [2] 87 c2 [2] c0 d3 [2] 8e df [2] 82 d5 [2] 95 de [2] 8e 90 [2] b3 }

  condition:
    any of them
}