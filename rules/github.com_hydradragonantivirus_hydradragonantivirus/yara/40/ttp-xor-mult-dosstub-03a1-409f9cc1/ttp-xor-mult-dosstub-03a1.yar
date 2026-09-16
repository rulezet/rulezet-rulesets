rule TTP_XOR_MULT_DOSStub_03a1 {
  strings:
    $key_03a1 = { 57 c9 [2] 23 d1 [2] 64 d3 [2] 23 c2 [2] 6d ce [2] 61 c4 [2] 76 cf [2] 6d 81 [2] 50 }

  condition:
    any of them
}