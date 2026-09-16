rule TTP_XOR_MULT_DOSStub_d3d3 {
  strings:
    $key_d3d3 = { 87 bb [2] f3 a3 [2] b4 a1 [2] f3 b0 [2] bd bc [2] b1 b6 [2] a6 bd [2] bd f3 [2] 80 }

  condition:
    any of them
}