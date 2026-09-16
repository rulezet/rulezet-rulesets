rule TTP_XOR_MULT_DOSStub_1cd6 {
  strings:
    $key_1cd6 = { 48 be [2] 3c a6 [2] 7b a4 [2] 3c b5 [2] 72 b9 [2] 7e b3 [2] 69 b8 [2] 72 f6 [2] 4f }

  condition:
    any of them
}