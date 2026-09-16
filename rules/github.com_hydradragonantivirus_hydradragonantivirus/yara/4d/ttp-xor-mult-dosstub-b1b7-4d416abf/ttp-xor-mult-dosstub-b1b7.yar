rule TTP_XOR_MULT_DOSStub_b1b7 {
  strings:
    $key_b1b7 = { e5 df [2] 91 c7 [2] d6 c5 [2] 91 d4 [2] df d8 [2] d3 d2 [2] c4 d9 [2] df 97 [2] e2 }

  condition:
    any of them
}