rule TTP_XOR_MULT_DOSStub_6fd6 {
  strings:
    $key_6fd6 = { 3b be [2] 4f a6 [2] 08 a4 [2] 4f b5 [2] 01 b9 [2] 0d b3 [2] 1a b8 [2] 01 f6 [2] 3c }

  condition:
    any of them
}