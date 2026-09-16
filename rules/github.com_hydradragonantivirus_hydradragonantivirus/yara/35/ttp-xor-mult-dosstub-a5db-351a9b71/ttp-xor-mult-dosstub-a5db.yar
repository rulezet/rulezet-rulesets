rule TTP_XOR_MULT_DOSStub_a5db {
  strings:
    $key_a5db = { f1 b3 [2] 85 ab [2] c2 a9 [2] 85 b8 [2] cb b4 [2] c7 be [2] d0 b5 [2] cb fb [2] f6 }

  condition:
    any of them
}