rule TTP_XOR_MULT_DOSStub_b2d5 {
  strings:
    $key_b2d5 = { e6 bd [2] 92 a5 [2] d5 a7 [2] 92 b6 [2] dc ba [2] d0 b0 [2] c7 bb [2] dc f5 [2] e1 }

  condition:
    any of them
}