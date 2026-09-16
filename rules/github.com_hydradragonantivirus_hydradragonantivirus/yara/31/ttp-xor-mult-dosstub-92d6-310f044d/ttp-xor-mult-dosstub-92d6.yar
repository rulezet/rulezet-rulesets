rule TTP_XOR_MULT_DOSStub_92d6 {
  strings:
    $key_92d6 = { c6 be [2] b2 a6 [2] f5 a4 [2] b2 b5 [2] fc b9 [2] f0 b3 [2] e7 b8 [2] fc f6 [2] c1 }

  condition:
    any of them
}