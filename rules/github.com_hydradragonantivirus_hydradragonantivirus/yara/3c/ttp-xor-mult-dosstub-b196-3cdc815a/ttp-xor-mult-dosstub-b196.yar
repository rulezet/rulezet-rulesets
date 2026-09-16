rule TTP_XOR_MULT_DOSStub_b196 {
  strings:
    $key_b196 = { e5 fe [2] 91 e6 [2] d6 e4 [2] 91 f5 [2] df f9 [2] d3 f3 [2] c4 f8 [2] df b6 [2] e2 }

  condition:
    any of them
}