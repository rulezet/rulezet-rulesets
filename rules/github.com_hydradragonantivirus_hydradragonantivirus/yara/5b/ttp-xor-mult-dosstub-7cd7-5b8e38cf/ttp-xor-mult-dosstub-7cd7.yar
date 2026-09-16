rule TTP_XOR_MULT_DOSStub_7cd7 {
  strings:
    $key_7cd7 = { 28 bf [2] 5c a7 [2] 1b a5 [2] 5c b4 [2] 12 b8 [2] 1e b2 [2] 09 b9 [2] 12 f7 [2] 2f }

  condition:
    any of them
}