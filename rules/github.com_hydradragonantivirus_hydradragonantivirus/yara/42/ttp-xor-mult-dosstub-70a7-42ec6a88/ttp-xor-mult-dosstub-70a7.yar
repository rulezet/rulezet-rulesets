rule TTP_XOR_MULT_DOSStub_70a7 {
  strings:
    $key_70a7 = { 24 cf [2] 50 d7 [2] 17 d5 [2] 50 c4 [2] 1e c8 [2] 12 c2 [2] 05 c9 [2] 1e 87 [2] 23 }

  condition:
    any of them
}