rule TTP_XOR_MULT_DOSStub_c1d3 {
  strings:
    $key_c1d3 = { 95 bb [2] e1 a3 [2] a6 a1 [2] e1 b0 [2] af bc [2] a3 b6 [2] b4 bd [2] af f3 [2] 92 }

  condition:
    any of them
}