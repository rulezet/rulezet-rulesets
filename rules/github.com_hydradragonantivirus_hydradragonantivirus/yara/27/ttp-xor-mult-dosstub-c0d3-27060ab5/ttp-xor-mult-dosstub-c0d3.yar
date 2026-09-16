rule TTP_XOR_MULT_DOSStub_c0d3 {
  strings:
    $key_c0d3 = { 94 bb [2] e0 a3 [2] a7 a1 [2] e0 b0 [2] ae bc [2] a2 b6 [2] b5 bd [2] ae f3 [2] 93 }

  condition:
    any of them
}