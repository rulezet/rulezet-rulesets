rule TTP_XOR_MULT_DOSStub_e0d1 {
  strings:
    $key_e0d1 = { b4 b9 [2] c0 a1 [2] 87 a3 [2] c0 b2 [2] 8e be [2] 82 b4 [2] 95 bf [2] 8e f1 [2] b3 }

  condition:
    any of them
}