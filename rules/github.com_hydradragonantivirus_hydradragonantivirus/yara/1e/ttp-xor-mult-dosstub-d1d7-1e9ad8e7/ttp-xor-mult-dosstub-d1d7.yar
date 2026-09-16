rule TTP_XOR_MULT_DOSStub_d1d7 {
  strings:
    $key_d1d7 = { 85 bf [2] f1 a7 [2] b6 a5 [2] f1 b4 [2] bf b8 [2] b3 b2 [2] a4 b9 [2] bf f7 [2] 82 }

  condition:
    any of them
}