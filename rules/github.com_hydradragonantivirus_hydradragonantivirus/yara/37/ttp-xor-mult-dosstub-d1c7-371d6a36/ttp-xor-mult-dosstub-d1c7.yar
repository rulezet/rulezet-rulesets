rule TTP_XOR_MULT_DOSStub_d1c7 {
  strings:
    $key_d1c7 = { 85 af [2] f1 b7 [2] b6 b5 [2] f1 a4 [2] bf a8 [2] b3 a2 [2] a4 a9 [2] bf e7 [2] 82 }

  condition:
    any of them
}