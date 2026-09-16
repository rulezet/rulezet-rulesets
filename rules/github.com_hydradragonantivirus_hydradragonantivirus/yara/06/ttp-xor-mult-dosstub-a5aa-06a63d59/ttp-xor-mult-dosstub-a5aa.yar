rule TTP_XOR_MULT_DOSStub_a5aa {
  strings:
    $key_a5aa = { f1 c2 [2] 85 da [2] c2 d8 [2] 85 c9 [2] cb c5 [2] c7 cf [2] d0 c4 [2] cb 8a [2] f6 }

  condition:
    any of them
}