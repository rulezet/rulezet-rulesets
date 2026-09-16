rule TTP_XOR_MULT_DOSStub_7cd0 {
  strings:
    $key_7cd0 = { 28 b8 [2] 5c a0 [2] 1b a2 [2] 5c b3 [2] 12 bf [2] 1e b5 [2] 09 be [2] 12 f0 [2] 2f }

  condition:
    any of them
}