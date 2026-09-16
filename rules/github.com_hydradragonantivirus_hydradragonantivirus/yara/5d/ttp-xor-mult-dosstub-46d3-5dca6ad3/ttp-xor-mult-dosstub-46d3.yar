rule TTP_XOR_MULT_DOSStub_46d3 {
  strings:
    $key_46d3 = { 12 bb [2] 66 a3 [2] 21 a1 [2] 66 b0 [2] 28 bc [2] 24 b6 [2] 33 bd [2] 28 f3 [2] 15 }

  condition:
    any of them
}