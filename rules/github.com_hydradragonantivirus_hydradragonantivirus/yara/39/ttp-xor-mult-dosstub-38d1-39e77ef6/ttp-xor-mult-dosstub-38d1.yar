rule TTP_XOR_MULT_DOSStub_38d1 {
  strings:
    $key_38d1 = { 6c b9 [2] 18 a1 [2] 5f a3 [2] 18 b2 [2] 56 be [2] 5a b4 [2] 4d bf [2] 56 f1 [2] 6b }

  condition:
    any of them
}