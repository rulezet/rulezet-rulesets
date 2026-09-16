rule TTP_XOR_MULT_DOSStub_95d6 {
  strings:
    $key_95d6 = { c1 be [2] b5 a6 [2] f2 a4 [2] b5 b5 [2] fb b9 [2] f7 b3 [2] e0 b8 [2] fb f6 [2] c6 }

  condition:
    any of them
}