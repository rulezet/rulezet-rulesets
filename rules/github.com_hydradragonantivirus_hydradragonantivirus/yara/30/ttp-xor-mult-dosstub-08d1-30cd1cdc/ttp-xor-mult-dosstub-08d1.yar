rule TTP_XOR_MULT_DOSStub_08d1 {
  strings:
    $key_08d1 = { 5c b9 [2] 28 a1 [2] 6f a3 [2] 28 b2 [2] 66 be [2] 6a b4 [2] 7d bf [2] 66 f1 [2] 5b }

  condition:
    any of them
}