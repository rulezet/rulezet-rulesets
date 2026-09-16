rule TTP_XOR_MULT_DOSStub_06d3 {
  strings:
    $key_06d3 = { 52 bb [2] 26 a3 [2] 61 a1 [2] 26 b0 [2] 68 bc [2] 64 b6 [2] 73 bd [2] 68 f3 [2] 55 }

  condition:
    any of them
}