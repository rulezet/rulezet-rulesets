rule TTP_XOR_MULT_DOSStub_e7d1 {
  strings:
    $key_e7d1 = { b3 b9 [2] c7 a1 [2] 80 a3 [2] c7 b2 [2] 89 be [2] 85 b4 [2] 92 bf [2] 89 f1 [2] b4 }

  condition:
    any of them
}