rule TTP_XOR_MULT_DOSStub_c4d3 {
  strings:
    $key_c4d3 = { 90 bb [2] e4 a3 [2] a3 a1 [2] e4 b0 [2] aa bc [2] a6 b6 [2] b1 bd [2] aa f3 [2] 97 }

  condition:
    any of them
}