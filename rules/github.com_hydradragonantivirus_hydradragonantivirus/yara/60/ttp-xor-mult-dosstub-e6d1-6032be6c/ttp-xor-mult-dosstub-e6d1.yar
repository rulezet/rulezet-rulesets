rule TTP_XOR_MULT_DOSStub_e6d1 {
  strings:
    $key_e6d1 = { b2 b9 [2] c6 a1 [2] 81 a3 [2] c6 b2 [2] 88 be [2] 84 b4 [2] 93 bf [2] 88 f1 [2] b5 }

  condition:
    any of them
}