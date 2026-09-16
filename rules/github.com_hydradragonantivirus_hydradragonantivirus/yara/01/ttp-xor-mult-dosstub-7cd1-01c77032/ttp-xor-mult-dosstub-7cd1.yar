rule TTP_XOR_MULT_DOSStub_7cd1 {
  strings:
    $key_7cd1 = { 28 b9 [2] 5c a1 [2] 1b a3 [2] 5c b2 [2] 12 be [2] 1e b4 [2] 09 bf [2] 12 f1 [2] 2f }

  condition:
    any of them
}