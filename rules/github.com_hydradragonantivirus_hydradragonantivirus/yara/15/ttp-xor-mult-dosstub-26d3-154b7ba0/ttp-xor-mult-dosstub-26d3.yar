rule TTP_XOR_MULT_DOSStub_26d3 {
  strings:
    $key_26d3 = { 72 bb [2] 06 a3 [2] 41 a1 [2] 06 b0 [2] 48 bc [2] 44 b6 [2] 53 bd [2] 48 f3 [2] 75 }

  condition:
    any of them
}