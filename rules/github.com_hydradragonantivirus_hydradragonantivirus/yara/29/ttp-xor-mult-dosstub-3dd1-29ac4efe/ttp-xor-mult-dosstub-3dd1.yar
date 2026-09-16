rule TTP_XOR_MULT_DOSStub_3dd1 {
  strings:
    $key_3dd1 = { 69 b9 [2] 1d a1 [2] 5a a3 [2] 1d b2 [2] 53 be [2] 5f b4 [2] 48 bf [2] 53 f1 [2] 6e }

  condition:
    any of them
}