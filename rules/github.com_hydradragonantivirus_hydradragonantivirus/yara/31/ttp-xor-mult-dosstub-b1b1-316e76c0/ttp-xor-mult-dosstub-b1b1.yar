rule TTP_XOR_MULT_DOSStub_b1b1 {
  strings:
    $key_b1b1 = { e5 d9 [2] 91 c1 [2] d6 c3 [2] 91 d2 [2] df de [2] d3 d4 [2] c4 df [2] df 91 [2] e2 }

  condition:
    any of them
}