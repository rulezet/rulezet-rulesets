rule TTP_XOR_MULT_DOSStub_a558 {
  strings:
    $key_a558 = { f1 30 [2] 85 28 [2] c2 2a [2] 85 3b [2] cb 37 [2] c7 3d [2] d0 36 [2] cb 78 [2] f6 }

  condition:
    any of them
}