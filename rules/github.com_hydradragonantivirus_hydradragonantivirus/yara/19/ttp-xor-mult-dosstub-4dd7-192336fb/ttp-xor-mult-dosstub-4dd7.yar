rule TTP_XOR_MULT_DOSStub_4dd7 {
  strings:
    $key_4dd7 = { 19 bf [2] 6d a7 [2] 2a a5 [2] 6d b4 [2] 23 b8 [2] 2f b2 [2] 38 b9 [2] 23 f7 [2] 1e }

  condition:
    any of them
}