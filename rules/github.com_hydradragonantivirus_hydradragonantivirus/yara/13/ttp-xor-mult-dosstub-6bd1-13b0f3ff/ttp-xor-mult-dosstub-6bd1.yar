rule TTP_XOR_MULT_DOSStub_6bd1 {
  strings:
    $key_6bd1 = { 3f b9 [2] 4b a1 [2] 0c a3 [2] 4b b2 [2] 05 be [2] 09 b4 [2] 1e bf [2] 05 f1 [2] 38 }

  condition:
    any of them
}