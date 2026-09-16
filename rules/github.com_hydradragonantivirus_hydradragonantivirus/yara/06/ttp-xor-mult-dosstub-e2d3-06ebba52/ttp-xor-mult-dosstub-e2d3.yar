rule TTP_XOR_MULT_DOSStub_e2d3 {
  strings:
    $key_e2d3 = { b6 bb [2] c2 a3 [2] 85 a1 [2] c2 b0 [2] 8c bc [2] 80 b6 [2] 97 bd [2] 8c f3 [2] b1 }

  condition:
    any of them
}