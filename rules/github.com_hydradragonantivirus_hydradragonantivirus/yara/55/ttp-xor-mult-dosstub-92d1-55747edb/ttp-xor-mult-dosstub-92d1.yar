rule TTP_XOR_MULT_DOSStub_92d1 {
  strings:
    $key_92d1 = { c6 b9 [2] b2 a1 [2] f5 a3 [2] b2 b2 [2] fc be [2] f0 b4 [2] e7 bf [2] fc f1 [2] c1 }

  condition:
    any of them
}