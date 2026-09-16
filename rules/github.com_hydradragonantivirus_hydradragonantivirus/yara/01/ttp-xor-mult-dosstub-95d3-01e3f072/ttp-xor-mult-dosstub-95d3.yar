rule TTP_XOR_MULT_DOSStub_95d3 {
  strings:
    $key_95d3 = { c1 bb [2] b5 a3 [2] f2 a1 [2] b5 b0 [2] fb bc [2] f7 b6 [2] e0 bd [2] fb f3 [2] c6 }

  condition:
    any of them
}