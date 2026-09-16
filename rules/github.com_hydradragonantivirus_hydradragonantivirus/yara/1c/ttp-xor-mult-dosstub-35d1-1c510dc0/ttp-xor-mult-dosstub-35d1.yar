rule TTP_XOR_MULT_DOSStub_35d1 {
  strings:
    $key_35d1 = { 61 b9 [2] 15 a1 [2] 52 a3 [2] 15 b2 [2] 5b be [2] 57 b4 [2] 40 bf [2] 5b f1 [2] 66 }

  condition:
    any of them
}