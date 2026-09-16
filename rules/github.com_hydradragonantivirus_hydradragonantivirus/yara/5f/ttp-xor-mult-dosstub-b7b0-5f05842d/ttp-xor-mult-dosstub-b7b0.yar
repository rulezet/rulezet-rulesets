rule TTP_XOR_MULT_DOSStub_b7b0 {
  strings:
    $key_b7b0 = { e3 d8 [2] 97 c0 [2] d0 c2 [2] 97 d3 [2] d9 df [2] d5 d5 [2] c2 de [2] d9 90 [2] e4 }

  condition:
    any of them
}