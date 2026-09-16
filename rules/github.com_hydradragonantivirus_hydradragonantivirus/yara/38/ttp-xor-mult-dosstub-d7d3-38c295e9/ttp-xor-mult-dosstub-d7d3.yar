rule TTP_XOR_MULT_DOSStub_d7d3 {
  strings:
    $key_d7d3 = { 83 bb [2] f7 a3 [2] b0 a1 [2] f7 b0 [2] b9 bc [2] b5 b6 [2] a2 bd [2] b9 f3 [2] 84 }

  condition:
    any of them
}