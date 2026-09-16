rule TTP_XOR_MULT_DOSStub_3bd1 {
  strings:
    $key_3bd1 = { 6f b9 [2] 1b a1 [2] 5c a3 [2] 1b b2 [2] 55 be [2] 59 b4 [2] 4e bf [2] 55 f1 [2] 68 }

  condition:
    any of them
}