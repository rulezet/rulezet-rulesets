rule TTP_XOR_MULT_DOSStub_30d3 {
  strings:
    $key_30d3 = { 64 bb [2] 10 a3 [2] 57 a1 [2] 10 b0 [2] 5e bc [2] 52 b6 [2] 45 bd [2] 5e f3 [2] 63 }

  condition:
    any of them
}