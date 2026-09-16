rule TTP_XOR_MULT_DOSStub_86b0 {
  strings:
    $key_86b0 = { d2 d8 [2] a6 c0 [2] e1 c2 [2] a6 d3 [2] e8 df [2] e4 d5 [2] f3 de [2] e8 90 [2] d5 }

  condition:
    any of them
}