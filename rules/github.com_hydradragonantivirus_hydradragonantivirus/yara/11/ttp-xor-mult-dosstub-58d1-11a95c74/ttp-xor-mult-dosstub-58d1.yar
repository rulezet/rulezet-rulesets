rule TTP_XOR_MULT_DOSStub_58d1 {
  strings:
    $key_58d1 = { 0c b9 [2] 78 a1 [2] 3f a3 [2] 78 b2 [2] 36 be [2] 3a b4 [2] 2d bf [2] 36 f1 [2] 0b }

  condition:
    any of them
}