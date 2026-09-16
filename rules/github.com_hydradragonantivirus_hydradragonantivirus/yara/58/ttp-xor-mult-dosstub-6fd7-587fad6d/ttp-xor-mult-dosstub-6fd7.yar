rule TTP_XOR_MULT_DOSStub_6fd7 {
  strings:
    $key_6fd7 = { 3b bf [2] 4f a7 [2] 08 a5 [2] 4f b4 [2] 01 b8 [2] 0d b2 [2] 1a b9 [2] 01 f7 [2] 3c }

  condition:
    any of them
}