rule TTP_XOR_MULT_DOSStub_78d0 {
  strings:
    $key_78d0 = { 2c b8 [2] 58 a0 [2] 1f a2 [2] 58 b3 [2] 16 bf [2] 1a b5 [2] 0d be [2] 16 f0 [2] 2b }

  condition:
    any of them
}