rule TTP_XOR_MULT_DOSStub_2cd1 {
  strings:
    $key_2cd1 = { 78 b9 [2] 0c a1 [2] 4b a3 [2] 0c b2 [2] 42 be [2] 4e b4 [2] 59 bf [2] 42 f1 [2] 7f }

  condition:
    any of them
}