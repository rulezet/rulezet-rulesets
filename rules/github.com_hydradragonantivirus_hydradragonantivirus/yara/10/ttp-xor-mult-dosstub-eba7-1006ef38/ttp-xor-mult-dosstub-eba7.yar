rule TTP_XOR_MULT_DOSStub_eba7 {
  strings:
    $key_eba7 = { bf cf [2] cb d7 [2] 8c d5 [2] cb c4 [2] 85 c8 [2] 89 c2 [2] 9e c9 [2] 85 87 [2] b8 }

  condition:
    any of them
}