rule TTP_XOR_MULT_DOSStub_50a1 {
  strings:
    $key_50a1 = { 04 c9 [2] 70 d1 [2] 37 d3 [2] 70 c2 [2] 3e ce [2] 32 c4 [2] 25 cf [2] 3e 81 [2] 03 }

  condition:
    any of them
}