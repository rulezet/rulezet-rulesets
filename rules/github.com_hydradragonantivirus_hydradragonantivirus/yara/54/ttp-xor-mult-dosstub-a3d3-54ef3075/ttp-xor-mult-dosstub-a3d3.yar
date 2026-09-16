rule TTP_XOR_MULT_DOSStub_a3d3 {
  strings:
    $key_a3d3 = { f7 bb [2] 83 a3 [2] c4 a1 [2] 83 b0 [2] cd bc [2] c1 b6 [2] d6 bd [2] cd f3 [2] f0 }

  condition:
    any of them
}