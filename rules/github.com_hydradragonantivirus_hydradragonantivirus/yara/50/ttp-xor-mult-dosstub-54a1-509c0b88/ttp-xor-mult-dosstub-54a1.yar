rule TTP_XOR_MULT_DOSStub_54a1 {
  strings:
    $key_54a1 = { 00 c9 [2] 74 d1 [2] 33 d3 [2] 74 c2 [2] 3a ce [2] 36 c4 [2] 21 cf [2] 3a 81 [2] 07 }

  condition:
    any of them
}