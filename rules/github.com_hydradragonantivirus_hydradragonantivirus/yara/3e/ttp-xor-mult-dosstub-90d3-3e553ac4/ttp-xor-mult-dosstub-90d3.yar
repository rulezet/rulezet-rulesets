rule TTP_XOR_MULT_DOSStub_90d3 {
  strings:
    $key_90d3 = { c4 bb [2] b0 a3 [2] f7 a1 [2] b0 b0 [2] fe bc [2] f2 b6 [2] e5 bd [2] fe f3 [2] c3 }

  condition:
    any of them
}