rule TTP_XOR_MULT_DOSStub_d1c8 {
  strings:
    $key_d1c8 = { 85 a0 [2] f1 b8 [2] b6 ba [2] f1 ab [2] bf a7 [2] b3 ad [2] a4 a6 [2] bf e8 [2] 82 }

  condition:
    any of them
}