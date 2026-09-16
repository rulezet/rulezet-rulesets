rule TTP_XOR_MULT_DOSStub_46d1 {
  strings:
    $key_46d1 = { 12 b9 [2] 66 a1 [2] 21 a3 [2] 66 b2 [2] 28 be [2] 24 b4 [2] 33 bf [2] 28 f1 [2] 15 }

  condition:
    any of them
}