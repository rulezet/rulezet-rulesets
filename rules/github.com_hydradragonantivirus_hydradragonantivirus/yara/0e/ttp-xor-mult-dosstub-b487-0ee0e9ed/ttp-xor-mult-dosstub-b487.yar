rule TTP_XOR_MULT_DOSStub_b487 {
  strings:
    $key_b487 = { e0 ef [2] 94 f7 [2] d3 f5 [2] 94 e4 [2] da e8 [2] d6 e2 [2] c1 e9 [2] da a7 [2] e7 }

  condition:
    any of them
}