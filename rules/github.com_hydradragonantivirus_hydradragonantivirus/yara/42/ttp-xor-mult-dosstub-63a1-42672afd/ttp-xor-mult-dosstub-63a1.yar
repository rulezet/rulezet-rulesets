rule TTP_XOR_MULT_DOSStub_63a1 {
  strings:
    $key_63a1 = { 37 c9 [2] 43 d1 [2] 04 d3 [2] 43 c2 [2] 0d ce [2] 01 c4 [2] 16 cf [2] 0d 81 [2] 30 }

  condition:
    any of them
}