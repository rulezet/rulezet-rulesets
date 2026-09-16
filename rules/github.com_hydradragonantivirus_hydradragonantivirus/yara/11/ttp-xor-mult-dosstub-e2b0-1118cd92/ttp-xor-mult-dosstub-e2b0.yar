rule TTP_XOR_MULT_DOSStub_e2b0 {
  strings:
    $key_e2b0 = { b6 d8 [2] c2 c0 [2] 85 c2 [2] c2 d3 [2] 8c df [2] 80 d5 [2] 97 de [2] 8c 90 [2] b1 }

  condition:
    any of them
}