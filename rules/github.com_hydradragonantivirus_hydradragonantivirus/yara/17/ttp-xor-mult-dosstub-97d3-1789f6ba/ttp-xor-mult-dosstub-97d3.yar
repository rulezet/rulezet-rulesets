rule TTP_XOR_MULT_DOSStub_97d3 {
  strings:
    $key_97d3 = { c3 bb [2] b7 a3 [2] f0 a1 [2] b7 b0 [2] f9 bc [2] f5 b6 [2] e2 bd [2] f9 f3 [2] c4 }

  condition:
    any of them
}