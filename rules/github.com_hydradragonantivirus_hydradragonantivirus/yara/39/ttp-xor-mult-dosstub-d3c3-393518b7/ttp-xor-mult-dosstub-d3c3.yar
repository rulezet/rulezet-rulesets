rule TTP_XOR_MULT_DOSStub_d3c3 {
  strings:
    $key_d3c3 = { 87 ab [2] f3 b3 [2] b4 b1 [2] f3 a0 [2] bd ac [2] b1 a6 [2] a6 ad [2] bd e3 [2] 80 }

  condition:
    any of them
}