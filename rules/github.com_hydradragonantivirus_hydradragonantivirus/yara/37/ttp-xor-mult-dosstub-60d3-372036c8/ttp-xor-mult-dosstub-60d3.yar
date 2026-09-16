rule TTP_XOR_MULT_DOSStub_60d3 {
  strings:
    $key_60d3 = { 34 bb [2] 40 a3 [2] 07 a1 [2] 40 b0 [2] 0e bc [2] 02 b6 [2] 15 bd [2] 0e f3 [2] 33 }

  condition:
    any of them
}