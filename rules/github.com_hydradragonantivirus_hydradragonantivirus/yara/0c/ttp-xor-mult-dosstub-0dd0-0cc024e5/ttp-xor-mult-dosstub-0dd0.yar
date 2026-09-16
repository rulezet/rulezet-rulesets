rule TTP_XOR_MULT_DOSStub_0dd0 {
  strings:
    $key_0dd0 = { 59 b8 [2] 2d a0 [2] 6a a2 [2] 2d b3 [2] 63 bf [2] 6f b5 [2] 78 be [2] 63 f0 [2] 5e }

  condition:
    any of them
}