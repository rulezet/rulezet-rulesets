rule TTP_XOR_MULT_DOSStub_4fd6 {
  strings:
    $key_4fd6 = { 1b be [2] 6f a6 [2] 28 a4 [2] 6f b5 [2] 21 b9 [2] 2d b3 [2] 3a b8 [2] 21 f6 [2] 1c }

  condition:
    any of them
}