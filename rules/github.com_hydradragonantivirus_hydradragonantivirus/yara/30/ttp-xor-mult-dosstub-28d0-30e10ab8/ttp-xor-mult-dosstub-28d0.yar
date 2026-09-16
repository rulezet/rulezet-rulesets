rule TTP_XOR_MULT_DOSStub_28d0 {
  strings:
    $key_28d0 = { 7c b8 [2] 08 a0 [2] 4f a2 [2] 08 b3 [2] 46 bf [2] 4a b5 [2] 5d be [2] 46 f0 [2] 7b }

  condition:
    any of them
}