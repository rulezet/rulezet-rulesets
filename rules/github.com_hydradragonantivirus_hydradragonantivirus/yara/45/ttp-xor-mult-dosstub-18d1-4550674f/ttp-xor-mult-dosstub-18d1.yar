rule TTP_XOR_MULT_DOSStub_18d1 {
  strings:
    $key_18d1 = { 4c b9 [2] 38 a1 [2] 7f a3 [2] 38 b2 [2] 76 be [2] 7a b4 [2] 6d bf [2] 76 f1 [2] 4b }

  condition:
    any of them
}