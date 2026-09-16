rule TTP_XOR_MULT_DOSStub_7dd1 {
  strings:
    $key_7dd1 = { 29 b9 [2] 5d a1 [2] 1a a3 [2] 5d b2 [2] 13 be [2] 1f b4 [2] 08 bf [2] 13 f1 [2] 2e }

  condition:
    any of them
}