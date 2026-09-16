rule TTP_XOR_MULT_DOSStub_71d3 {
  strings:
    $key_71d3 = { 25 bb [2] 51 a3 [2] 16 a1 [2] 51 b0 [2] 1f bc [2] 13 b6 [2] 04 bd [2] 1f f3 [2] 22 }

  condition:
    any of them
}