rule TTP_XOR_MULT_DOSStub_b1b0 {
  strings:
    $key_b1b0 = { e5 d8 [2] 91 c0 [2] d6 c2 [2] 91 d3 [2] df df [2] d3 d5 [2] c4 de [2] df 90 [2] e2 }

  condition:
    any of them
}