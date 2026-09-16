rule TTP_XOR_MULT_DOSStub_a2d3 {
  strings:
    $key_a2d3 = { f6 bb [2] 82 a3 [2] c5 a1 [2] 82 b0 [2] cc bc [2] c0 b6 [2] d7 bd [2] cc f3 [2] f1 }

  condition:
    any of them
}