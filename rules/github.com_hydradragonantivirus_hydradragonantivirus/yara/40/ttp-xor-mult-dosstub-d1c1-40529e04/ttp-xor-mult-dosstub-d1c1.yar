rule TTP_XOR_MULT_DOSStub_d1c1 {
  strings:
    $key_d1c1 = { 85 a9 [2] f1 b1 [2] b6 b3 [2] f1 a2 [2] bf ae [2] b3 a4 [2] a4 af [2] bf e1 [2] 82 }

  condition:
    any of them
}