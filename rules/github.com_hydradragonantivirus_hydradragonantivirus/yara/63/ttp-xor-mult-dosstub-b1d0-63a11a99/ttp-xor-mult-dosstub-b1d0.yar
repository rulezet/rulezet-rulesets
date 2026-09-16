rule TTP_XOR_MULT_DOSStub_b1d0 {
  strings:
    $key_b1d0 = { e5 b8 [2] 91 a0 [2] d6 a2 [2] 91 b3 [2] df bf [2] d3 b5 [2] c4 be [2] df f0 [2] e2 }

  condition:
    any of them
}