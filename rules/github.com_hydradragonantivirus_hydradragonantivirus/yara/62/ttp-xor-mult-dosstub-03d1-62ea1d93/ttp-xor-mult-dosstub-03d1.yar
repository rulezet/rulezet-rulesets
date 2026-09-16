rule TTP_XOR_MULT_DOSStub_03d1 {
  strings:
    $key_03d1 = { 57 b9 [2] 23 a1 [2] 64 a3 [2] 23 b2 [2] 6d be [2] 61 b4 [2] 76 bf [2] 6d f1 [2] 50 }

  condition:
    any of them
}