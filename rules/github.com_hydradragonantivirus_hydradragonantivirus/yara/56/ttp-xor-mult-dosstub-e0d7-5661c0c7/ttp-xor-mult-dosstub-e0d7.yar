rule TTP_XOR_MULT_DOSStub_e0d7 {
  strings:
    $key_e0d7 = { b4 bf [2] c0 a7 [2] 87 a5 [2] c0 b4 [2] 8e b8 [2] 82 b2 [2] 95 b9 [2] 8e f7 [2] b3 }

  condition:
    any of them
}