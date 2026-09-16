rule TTP_XOR_MULT_DOSStub_3cd7 {
  strings:
    $key_3cd7 = { 68 bf [2] 1c a7 [2] 5b a5 [2] 1c b4 [2] 52 b8 [2] 5e b2 [2] 49 b9 [2] 52 f7 [2] 6f }

  condition:
    any of them
}