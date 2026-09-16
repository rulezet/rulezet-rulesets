rule TTP_XOR_MULT_DOSStub_4cd7 {
  strings:
    $key_4cd7 = { 18 bf [2] 6c a7 [2] 2b a5 [2] 6c b4 [2] 22 b8 [2] 2e b2 [2] 39 b9 [2] 22 f7 [2] 1f }

  condition:
    any of them
}