rule TTP_XOR_MULT_DOSStub_4ac7 {
  strings:
    $key_4ac7 = { 1e af [2] 6a b7 [2] 2d b5 [2] 6a a4 [2] 24 a8 [2] 28 a2 [2] 3f a9 [2] 24 e7 [2] 19 }

  condition:
    any of them
}