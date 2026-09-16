rule TTP_XOR_MULT_DOSStub_d1c3 {
  strings:
    $key_d1c3 = { 85 ab [2] f1 b3 [2] b6 b1 [2] f1 a0 [2] bf ac [2] b3 a6 [2] a4 ad [2] bf e3 [2] 82 }

  condition:
    any of them
}