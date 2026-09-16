rule TTP_XOR_MULT_DOSStub_7bd1 {
  strings:
    $key_7bd1 = { 2f b9 [2] 5b a1 [2] 1c a3 [2] 5b b2 [2] 15 be [2] 19 b4 [2] 0e bf [2] 15 f1 [2] 28 }

  condition:
    any of them
}