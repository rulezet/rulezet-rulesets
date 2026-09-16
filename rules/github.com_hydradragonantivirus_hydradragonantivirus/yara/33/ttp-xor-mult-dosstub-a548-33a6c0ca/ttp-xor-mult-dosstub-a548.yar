rule TTP_XOR_MULT_DOSStub_a548 {
  strings:
    $key_a548 = { f1 20 [2] 85 38 [2] c2 3a [2] 85 2b [2] cb 27 [2] c7 2d [2] d0 26 [2] cb 68 [2] f6 }

  condition:
    any of them
}