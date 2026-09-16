rule TTP_XOR_MULT_DOSStub_d6d3 {
  strings:
    $key_d6d3 = { 82 bb [2] f6 a3 [2] b1 a1 [2] f6 b0 [2] b8 bc [2] b4 b6 [2] a3 bd [2] b8 f3 [2] 85 }

  condition:
    any of them
}