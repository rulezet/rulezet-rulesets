rule TTP_XOR_MULT_DOSStub_bed6 {
  strings:
    $key_bed6 = { ea be [2] 9e a6 [2] d9 a4 [2] 9e b5 [2] d0 b9 [2] dc b3 [2] cb b8 [2] d0 f6 [2] ed }

  condition:
    any of them
}