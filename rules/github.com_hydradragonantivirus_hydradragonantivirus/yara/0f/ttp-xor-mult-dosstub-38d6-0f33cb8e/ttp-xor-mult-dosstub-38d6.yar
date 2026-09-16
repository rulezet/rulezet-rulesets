rule TTP_XOR_MULT_DOSStub_38d6 {
  strings:
    $key_38d6 = { 6c be [2] 18 a6 [2] 5f a4 [2] 18 b5 [2] 56 b9 [2] 5a b3 [2] 4d b8 [2] 56 f6 [2] 6b }

  condition:
    any of them
}