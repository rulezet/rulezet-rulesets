rule TTP_XOR_MULT_DOSStub_d2d3 {
  strings:
    $key_d2d3 = { 86 bb [2] f2 a3 [2] b5 a1 [2] f2 b0 [2] bc bc [2] b0 b6 [2] a7 bd [2] bc f3 [2] 81 }

  condition:
    any of them
}