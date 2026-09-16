rule TTP_XOR_MULT_DOSStub_1ac7 {
  strings:
    $key_1ac7 = { 4e af [2] 3a b7 [2] 7d b5 [2] 3a a4 [2] 74 a8 [2] 78 a2 [2] 6f a9 [2] 74 e7 [2] 49 }

  condition:
    any of them
}