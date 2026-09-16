rule TTP_XOR_MULT_DOSStub_68d0 {
  strings:
    $key_68d0 = { 3c b8 [2] 48 a0 [2] 0f a2 [2] 48 b3 [2] 06 bf [2] 0a b5 [2] 1d be [2] 06 f0 [2] 3b }

  condition:
    any of them
}