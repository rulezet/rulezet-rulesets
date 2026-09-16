rule TTP_XOR_MULT_DOSStub_bed3 {
  strings:
    $key_bed3 = { ea bb [2] 9e a3 [2] d9 a1 [2] 9e b0 [2] d0 bc [2] dc b6 [2] cb bd [2] d0 f3 [2] ed }

  condition:
    any of them
}