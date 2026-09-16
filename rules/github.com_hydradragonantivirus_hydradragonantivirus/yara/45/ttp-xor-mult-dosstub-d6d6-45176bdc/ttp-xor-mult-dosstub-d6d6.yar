rule TTP_XOR_MULT_DOSStub_d6d6 {
  strings:
    $key_d6d6 = { 82 be [2] f6 a6 [2] b1 a4 [2] f6 b5 [2] b8 b9 [2] b4 b3 [2] a3 b8 [2] b8 f6 [2] 85 }

  condition:
    any of them
}