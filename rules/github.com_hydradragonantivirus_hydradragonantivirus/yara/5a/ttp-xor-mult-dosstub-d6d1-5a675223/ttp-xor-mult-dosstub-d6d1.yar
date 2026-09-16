rule TTP_XOR_MULT_DOSStub_d6d1 {
  strings:
    $key_d6d1 = { 82 b9 [2] f6 a1 [2] b1 a3 [2] f6 b2 [2] b8 be [2] b4 b4 [2] a3 bf [2] b8 f1 [2] 85 }

  condition:
    any of them
}