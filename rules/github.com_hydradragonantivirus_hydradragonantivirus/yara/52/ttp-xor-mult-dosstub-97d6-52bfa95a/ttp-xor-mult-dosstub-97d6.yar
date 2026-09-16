rule TTP_XOR_MULT_DOSStub_97d6 {
  strings:
    $key_97d6 = { c3 be [2] b7 a6 [2] f0 a4 [2] b7 b5 [2] f9 b9 [2] f5 b3 [2] e2 b8 [2] f9 f6 [2] c4 }

  condition:
    any of them
}