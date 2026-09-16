rule TTP_XOR_MULT_DOSStub_b4c0 {
  strings:
    $key_b4c0 = { e0 a8 [2] 94 b0 [2] d3 b2 [2] 94 a3 [2] da af [2] d6 a5 [2] c1 ae [2] da e0 [2] e7 }

  condition:
    any of them
}