rule TTP_XOR_MULT_DOSStub_e5b0 {
  strings:
    $key_e5b0 = { b1 d8 [2] c5 c0 [2] 82 c2 [2] c5 d3 [2] 8b df [2] 87 d5 [2] 90 de [2] 8b 90 [2] b6 }

  condition:
    any of them
}