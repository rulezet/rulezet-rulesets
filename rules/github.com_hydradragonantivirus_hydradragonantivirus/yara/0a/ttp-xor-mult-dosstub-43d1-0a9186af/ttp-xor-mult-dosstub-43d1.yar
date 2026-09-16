rule TTP_XOR_MULT_DOSStub_43d1 {
  strings:
    $key_43d1 = { 17 b9 [2] 63 a1 [2] 24 a3 [2] 63 b2 [2] 2d be [2] 21 b4 [2] 36 bf [2] 2d f1 [2] 10 }

  condition:
    any of them
}