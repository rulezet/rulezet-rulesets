rule TTP_XOR_MULT_DOSStub_f7d3 {
  strings:
    $key_f7d3 = { a3 bb [2] d7 a3 [2] 90 a1 [2] d7 b0 [2] 99 bc [2] 95 b6 [2] 82 bd [2] 99 f3 [2] a4 }

  condition:
    any of them
}