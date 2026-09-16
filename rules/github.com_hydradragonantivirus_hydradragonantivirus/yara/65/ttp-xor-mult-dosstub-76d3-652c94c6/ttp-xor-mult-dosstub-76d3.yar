rule TTP_XOR_MULT_DOSStub_76d3 {
  strings:
    $key_76d3 = { 22 bb [2] 56 a3 [2] 11 a1 [2] 56 b0 [2] 18 bc [2] 14 b6 [2] 03 bd [2] 18 f3 [2] 25 }

  condition:
    any of them
}