rule TTP_XOR_MULT_DOSStub_73d3 {
  strings:
    $key_73d3 = { 27 bb [2] 53 a3 [2] 14 a1 [2] 53 b0 [2] 1d bc [2] 11 b6 [2] 06 bd [2] 1d f3 [2] 20 }

  condition:
    any of them
}