rule TTP_XOR_MULT_DOSStub_e3d3 {
  strings:
    $key_e3d3 = { b7 bb [2] c3 a3 [2] 84 a1 [2] c3 b0 [2] 8d bc [2] 81 b6 [2] 96 bd [2] 8d f3 [2] b0 }

  condition:
    any of them
}