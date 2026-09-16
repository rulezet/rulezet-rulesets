rule TTP_XOR_MULT_DOSStub_43d3 {
  strings:
    $key_43d3 = { 17 bb [2] 63 a3 [2] 24 a1 [2] 63 b0 [2] 2d bc [2] 21 b6 [2] 36 bd [2] 2d f3 [2] 10 }

  condition:
    any of them
}