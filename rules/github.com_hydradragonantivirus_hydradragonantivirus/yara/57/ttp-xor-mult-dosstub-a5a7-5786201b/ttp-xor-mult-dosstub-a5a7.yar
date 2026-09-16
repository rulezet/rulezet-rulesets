rule TTP_XOR_MULT_DOSStub_a5a7 {
  strings:
    $key_a5a7 = { f1 cf [2] 85 d7 [2] c2 d5 [2] 85 c4 [2] cb c8 [2] c7 c2 [2] d0 c9 [2] cb 87 [2] f6 }

  condition:
    any of them
}