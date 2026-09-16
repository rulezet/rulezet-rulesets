rule TTP_XOR_MULT_DOSStub_c5d3 {
  strings:
    $key_c5d3 = { 91 bb [2] e5 a3 [2] a2 a1 [2] e5 b0 [2] ab bc [2] a7 b6 [2] b0 bd [2] ab f3 [2] 96 }

  condition:
    any of them
}