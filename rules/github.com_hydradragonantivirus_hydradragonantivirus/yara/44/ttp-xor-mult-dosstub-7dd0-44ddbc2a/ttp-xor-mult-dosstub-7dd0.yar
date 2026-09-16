rule TTP_XOR_MULT_DOSStub_7dd0 {
  strings:
    $key_7dd0 = { 29 b8 [2] 5d a0 [2] 1a a2 [2] 5d b3 [2] 13 bf [2] 1f b5 [2] 08 be [2] 13 f0 [2] 2e }

  condition:
    any of them
}