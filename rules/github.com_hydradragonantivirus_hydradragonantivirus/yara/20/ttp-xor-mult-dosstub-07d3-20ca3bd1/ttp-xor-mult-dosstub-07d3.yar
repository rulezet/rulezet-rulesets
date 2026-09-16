rule TTP_XOR_MULT_DOSStub_07d3 {
  strings:
    $key_07d3 = { 53 bb [2] 27 a3 [2] 60 a1 [2] 27 b0 [2] 69 bc [2] 65 b6 [2] 72 bd [2] 69 f3 [2] 54 }

  condition:
    any of them
}