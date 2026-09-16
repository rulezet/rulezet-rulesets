rule TTP_XOR_MULT_DOSStub_eba1 {
  strings:
    $key_eba1 = { bf c9 [2] cb d1 [2] 8c d3 [2] cb c2 [2] 85 ce [2] 89 c4 [2] 9e cf [2] 85 81 [2] b8 }

  condition:
    any of them
}