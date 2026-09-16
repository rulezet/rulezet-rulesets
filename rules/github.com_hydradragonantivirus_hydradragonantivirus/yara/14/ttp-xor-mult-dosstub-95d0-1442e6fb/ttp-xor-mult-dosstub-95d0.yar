rule TTP_XOR_MULT_DOSStub_95d0 {
  strings:
    $key_95d0 = { c1 b8 [2] b5 a0 [2] f2 a2 [2] b5 b3 [2] fb bf [2] f7 b5 [2] e0 be [2] fb f0 [2] c6 }

  condition:
    any of them
}