rule TTP_XOR_MULT_DOSStub_a535 {
  strings:
    $key_a535 = { f1 5d [2] 85 45 [2] c2 47 [2] 85 56 [2] cb 5a [2] c7 50 [2] d0 5b [2] cb 15 [2] f6 }

  condition:
    any of them
}