rule TTP_XOR_MULT_DOSStub_3ad7 {
  strings:
    $key_3ad7 = { 6e bf [2] 1a a7 [2] 5d a5 [2] 1a b4 [2] 54 b8 [2] 58 b2 [2] 4f b9 [2] 54 f7 [2] 69 }

  condition:
    any of them
}