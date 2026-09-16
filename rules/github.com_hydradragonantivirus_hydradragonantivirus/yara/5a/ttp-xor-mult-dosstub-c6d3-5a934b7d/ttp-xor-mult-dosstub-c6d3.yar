rule TTP_XOR_MULT_DOSStub_c6d3 {
  strings:
    $key_c6d3 = { 92 bb [2] e6 a3 [2] a1 a1 [2] e6 b0 [2] a8 bc [2] a4 b6 [2] b3 bd [2] a8 f3 [2] 95 }

  condition:
    any of them
}