rule TTP_XOR_MULT_DOSStub_28d1 {
  strings:
    $key_28d1 = { 7c b9 [2] 08 a1 [2] 4f a3 [2] 08 b2 [2] 46 be [2] 4a b4 [2] 5d bf [2] 46 f1 [2] 7b }

  condition:
    any of them
}