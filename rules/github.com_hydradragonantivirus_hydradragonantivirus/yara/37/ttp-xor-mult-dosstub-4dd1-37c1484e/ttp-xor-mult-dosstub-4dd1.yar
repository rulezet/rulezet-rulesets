rule TTP_XOR_MULT_DOSStub_4dd1 {
  strings:
    $key_4dd1 = { 19 b9 [2] 6d a1 [2] 2a a3 [2] 6d b2 [2] 23 be [2] 2f b4 [2] 38 bf [2] 23 f1 [2] 1e }

  condition:
    any of them
}