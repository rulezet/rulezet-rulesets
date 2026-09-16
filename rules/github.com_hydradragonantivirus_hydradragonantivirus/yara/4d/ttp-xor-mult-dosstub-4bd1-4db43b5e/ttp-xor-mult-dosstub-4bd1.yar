rule TTP_XOR_MULT_DOSStub_4bd1 {
  strings:
    $key_4bd1 = { 1f b9 [2] 6b a1 [2] 2c a3 [2] 6b b2 [2] 25 be [2] 29 b4 [2] 3e bf [2] 25 f1 [2] 18 }

  condition:
    any of them
}