rule TTP_XOR_MULT_DOSStub_58d0 {
  strings:
    $key_58d0 = { 0c b8 [2] 78 a0 [2] 3f a2 [2] 78 b3 [2] 36 bf [2] 3a b5 [2] 2d be [2] 36 f0 [2] 0b }

  condition:
    any of them
}