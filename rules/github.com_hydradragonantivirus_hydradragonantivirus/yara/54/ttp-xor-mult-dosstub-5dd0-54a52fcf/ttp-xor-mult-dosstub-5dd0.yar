rule TTP_XOR_MULT_DOSStub_5dd0 {
  strings:
    $key_5dd0 = { 09 b8 [2] 7d a0 [2] 3a a2 [2] 7d b3 [2] 33 bf [2] 3f b5 [2] 28 be [2] 33 f0 [2] 0e }

  condition:
    any of them
}