rule TTP_XOR_MULT_DOSStub_c1c3 {
  strings:
    $key_c1c3 = { 95 ab [2] e1 b3 [2] a6 b1 [2] e1 a0 [2] af ac [2] a3 a6 [2] b4 ad [2] af e3 [2] 92 }

  condition:
    any of them
}