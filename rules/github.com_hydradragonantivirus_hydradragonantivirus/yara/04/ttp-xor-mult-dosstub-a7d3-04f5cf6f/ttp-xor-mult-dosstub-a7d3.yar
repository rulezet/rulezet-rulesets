rule TTP_XOR_MULT_DOSStub_a7d3 {
  strings:
    $key_a7d3 = { f3 bb [2] 87 a3 [2] c0 a1 [2] 87 b0 [2] c9 bc [2] c5 b6 [2] d2 bd [2] c9 f3 [2] f4 }

  condition:
    any of them
}