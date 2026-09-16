rule TTP_XOR_MULT_DOSStub_5fd6 {
  strings:
    $key_5fd6 = { 0b be [2] 7f a6 [2] 38 a4 [2] 7f b5 [2] 31 b9 [2] 3d b3 [2] 2a b8 [2] 31 f6 [2] 0c }

  condition:
    any of them
}