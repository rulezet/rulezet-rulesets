rule TTP_XOR_MULT_DOSStub_c3d3 {
  strings:
    $key_c3d3 = { 97 bb [2] e3 a3 [2] a4 a1 [2] e3 b0 [2] ad bc [2] a1 b6 [2] b6 bd [2] ad f3 [2] 90 }

  condition:
    any of them
}