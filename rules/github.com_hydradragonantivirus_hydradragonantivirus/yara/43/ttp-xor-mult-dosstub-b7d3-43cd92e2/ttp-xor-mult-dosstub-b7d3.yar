rule TTP_XOR_MULT_DOSStub_b7d3 {
  strings:
    $key_b7d3 = { e3 bb [2] 97 a3 [2] d0 a1 [2] 97 b0 [2] d9 bc [2] d5 b6 [2] c2 bd [2] d9 f3 [2] e4 }

  condition:
    any of them
}