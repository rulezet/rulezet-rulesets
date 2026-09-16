rule TTP_XOR_MULT_DOSStub_6dd7 {
  strings:
    $key_6dd7 = { 39 bf [2] 4d a7 [2] 0a a5 [2] 4d b4 [2] 03 b8 [2] 0f b2 [2] 18 b9 [2] 03 f7 [2] 3e }

  condition:
    any of them
}