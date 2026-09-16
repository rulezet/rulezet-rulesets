rule TTP_XOR_MULT_DOSStub_bed2 {
  strings:
    $key_bed2 = { ea ba [2] 9e a2 [2] d9 a0 [2] 9e b1 [2] d0 bd [2] dc b7 [2] cb bc [2] d0 f2 [2] ed }

  condition:
    any of them
}