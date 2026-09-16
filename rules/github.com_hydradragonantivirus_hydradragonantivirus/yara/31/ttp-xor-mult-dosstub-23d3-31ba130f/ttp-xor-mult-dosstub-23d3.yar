rule TTP_XOR_MULT_DOSStub_23d3 {
  strings:
    $key_23d3 = { 77 bb [2] 03 a3 [2] 44 a1 [2] 03 b0 [2] 4d bc [2] 41 b6 [2] 56 bd [2] 4d f3 [2] 70 }

  condition:
    any of them
}