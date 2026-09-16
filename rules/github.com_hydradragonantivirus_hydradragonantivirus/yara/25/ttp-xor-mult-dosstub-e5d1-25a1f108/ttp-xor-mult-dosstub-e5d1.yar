rule TTP_XOR_MULT_DOSStub_e5d1 {
  strings:
    $key_e5d1 = { b1 b9 [2] c5 a1 [2] 82 a3 [2] c5 b2 [2] 8b be [2] 87 b4 [2] 90 bf [2] 8b f1 [2] b6 }

  condition:
    any of them
}