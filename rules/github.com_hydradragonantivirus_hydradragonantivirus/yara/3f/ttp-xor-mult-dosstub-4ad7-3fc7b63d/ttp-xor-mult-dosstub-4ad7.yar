rule TTP_XOR_MULT_DOSStub_4ad7 {
  strings:
    $key_4ad7 = { 1e bf [2] 6a a7 [2] 2d a5 [2] 6a b4 [2] 24 b8 [2] 28 b2 [2] 3f b9 [2] 24 f7 [2] 19 }

  condition:
    any of them
}