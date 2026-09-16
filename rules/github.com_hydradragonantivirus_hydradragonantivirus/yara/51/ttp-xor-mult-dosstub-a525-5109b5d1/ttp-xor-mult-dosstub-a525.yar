rule TTP_XOR_MULT_DOSStub_a525 {
  strings:
    $key_a525 = { f1 4d [2] 85 55 [2] c2 57 [2] 85 46 [2] cb 4a [2] c7 40 [2] d0 4b [2] cb 05 [2] f6 }

  condition:
    any of them
}