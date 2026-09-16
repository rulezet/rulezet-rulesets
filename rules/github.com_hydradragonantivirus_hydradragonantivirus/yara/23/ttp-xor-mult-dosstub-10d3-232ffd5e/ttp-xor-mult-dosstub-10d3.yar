rule TTP_XOR_MULT_DOSStub_10d3 {
  strings:
    $key_10d3 = { 44 bb [2] 30 a3 [2] 77 a1 [2] 30 b0 [2] 7e bc [2] 72 b6 [2] 65 bd [2] 7e f3 [2] 43 }

  condition:
    any of them
}