rule TTP_XOR_MULT_DOSStub_b2d3 {
  strings:
    $key_b2d3 = { e6 bb [2] 92 a3 [2] d5 a1 [2] 92 b0 [2] dc bc [2] d0 b6 [2] c7 bd [2] dc f3 [2] e1 }

  condition:
    any of them
}