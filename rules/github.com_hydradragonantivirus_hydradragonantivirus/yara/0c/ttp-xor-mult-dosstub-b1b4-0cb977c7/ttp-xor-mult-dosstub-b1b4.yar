rule TTP_XOR_MULT_DOSStub_b1b4 {
  strings:
    $key_b1b4 = { e5 dc [2] 91 c4 [2] d6 c6 [2] 91 d7 [2] df db [2] d3 d1 [2] c4 da [2] df 94 [2] e2 }

  condition:
    any of them
}