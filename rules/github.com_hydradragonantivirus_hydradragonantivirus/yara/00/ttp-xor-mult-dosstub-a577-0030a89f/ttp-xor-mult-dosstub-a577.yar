rule TTP_XOR_MULT_DOSStub_a577 {
  strings:
    $key_a577 = { f1 1f [2] 85 07 [2] c2 05 [2] 85 14 [2] cb 18 [2] c7 12 [2] d0 19 [2] cb 57 [2] f6 }

  condition:
    any of them
}