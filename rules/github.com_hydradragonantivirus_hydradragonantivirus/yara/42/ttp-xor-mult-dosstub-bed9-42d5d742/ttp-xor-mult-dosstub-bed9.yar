rule TTP_XOR_MULT_DOSStub_bed9 {
  strings:
    $key_bed9 = { ea b1 [2] 9e a9 [2] d9 ab [2] 9e ba [2] d0 b6 [2] dc bc [2] cb b7 [2] d0 f9 [2] ed }

  condition:
    any of them
}