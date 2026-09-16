rule TTP_XOR_MULT_DOSStub_0ac7 {
  strings:
    $key_0ac7 = { 5e af [2] 2a b7 [2] 6d b5 [2] 2a a4 [2] 64 a8 [2] 68 a2 [2] 7f a9 [2] 64 e7 [2] 59 }

  condition:
    any of them
}