rule TTP_XOR_MULT_DOSStub_7dd7 {
  strings:
    $key_7dd7 = { 29 bf [2] 5d a7 [2] 1a a5 [2] 5d b4 [2] 13 b8 [2] 1f b2 [2] 08 b9 [2] 13 f7 [2] 2e }

  condition:
    any of them
}