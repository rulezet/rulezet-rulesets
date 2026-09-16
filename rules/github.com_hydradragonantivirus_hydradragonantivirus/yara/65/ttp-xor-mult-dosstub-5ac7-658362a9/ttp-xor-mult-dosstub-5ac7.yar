rule TTP_XOR_MULT_DOSStub_5ac7 {
  strings:
    $key_5ac7 = { 0e af [2] 7a b7 [2] 3d b5 [2] 7a a4 [2] 34 a8 [2] 38 a2 [2] 2f a9 [2] 34 e7 [2] 09 }

  condition:
    any of them
}