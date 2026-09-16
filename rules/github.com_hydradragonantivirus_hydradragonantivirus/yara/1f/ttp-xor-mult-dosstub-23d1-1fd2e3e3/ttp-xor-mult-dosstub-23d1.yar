rule TTP_XOR_MULT_DOSStub_23d1 {
  strings:
    $key_23d1 = { 77 b9 [2] 03 a1 [2] 44 a3 [2] 03 b2 [2] 4d be [2] 41 b4 [2] 56 bf [2] 4d f1 [2] 70 }

  condition:
    any of them
}