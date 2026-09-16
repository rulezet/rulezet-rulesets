rule TTP_XOR_MULT_DOSStub_4fd0 {
  strings:
    $key_4fd0 = { 1b b8 [2] 6f a0 [2] 28 a2 [2] 6f b3 [2] 21 bf [2] 2d b5 [2] 3a be [2] 21 f0 [2] 1c }

  condition:
    any of them
}