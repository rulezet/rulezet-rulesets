rule TTP_XOR_MULT_DOSStub_a555 {
  strings:
    $key_a555 = { f1 3d [2] 85 25 [2] c2 27 [2] 85 36 [2] cb 3a [2] c7 30 [2] d0 3b [2] cb 75 [2] f6 }

  condition:
    any of them
}