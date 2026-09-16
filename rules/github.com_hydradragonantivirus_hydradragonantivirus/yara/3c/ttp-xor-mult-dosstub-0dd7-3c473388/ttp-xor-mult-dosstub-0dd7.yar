rule TTP_XOR_MULT_DOSStub_0dd7 {
  strings:
    $key_0dd7 = { 59 bf [2] 2d a7 [2] 6a a5 [2] 2d b4 [2] 63 b8 [2] 6f b2 [2] 78 b9 [2] 63 f7 [2] 5e }

  condition:
    any of them
}