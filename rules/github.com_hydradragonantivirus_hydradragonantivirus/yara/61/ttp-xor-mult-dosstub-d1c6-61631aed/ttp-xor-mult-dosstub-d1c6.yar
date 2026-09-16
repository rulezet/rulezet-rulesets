rule TTP_XOR_MULT_DOSStub_d1c6 {
  strings:
    $key_d1c6 = { 85 ae [2] f1 b6 [2] b6 b4 [2] f1 a5 [2] bf a9 [2] b3 a3 [2] a4 a8 [2] bf e6 [2] 82 }

  condition:
    any of them
}