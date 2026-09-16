rule TTP_XOR_MULT_DOSStub_39d0 {
  strings:
    $key_39d0 = { 6d b8 [2] 19 a0 [2] 5e a2 [2] 19 b3 [2] 57 bf [2] 5b b5 [2] 4c be [2] 57 f0 [2] 6a }

  condition:
    any of them
}