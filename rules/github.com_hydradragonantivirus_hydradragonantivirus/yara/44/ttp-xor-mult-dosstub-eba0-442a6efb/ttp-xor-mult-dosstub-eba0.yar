rule TTP_XOR_MULT_DOSStub_eba0 {
  strings:
    $key_eba0 = { bf c8 [2] cb d0 [2] 8c d2 [2] cb c3 [2] 85 cf [2] 89 c5 [2] 9e ce [2] 85 80 [2] b8 }

  condition:
    any of them
}