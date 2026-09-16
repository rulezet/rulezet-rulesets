rule TTP_XOR_MULT_DOSStub_03d3 {
  strings:
    $key_03d3 = { 57 bb [2] 23 a3 [2] 64 a1 [2] 23 b0 [2] 6d bc [2] 61 b6 [2] 76 bd [2] 6d f3 [2] 50 }

  condition:
    any of them
}