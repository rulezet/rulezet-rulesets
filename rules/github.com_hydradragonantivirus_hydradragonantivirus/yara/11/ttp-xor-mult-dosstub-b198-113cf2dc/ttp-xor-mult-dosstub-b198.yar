rule TTP_XOR_MULT_DOSStub_b198 {
  strings:
    $key_b198 = { e5 f0 [2] 91 e8 [2] d6 ea [2] 91 fb [2] df f7 [2] d3 fd [2] c4 f6 [2] df b8 [2] e2 }

  condition:
    any of them
}