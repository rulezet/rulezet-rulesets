rule TTP_XOR_MULT_DOSStub_60a1 {
  strings:
    $key_60a1 = { 34 c9 [2] 40 d1 [2] 07 d3 [2] 40 c2 [2] 0e ce [2] 02 c4 [2] 15 cf [2] 0e 81 [2] 33 }

  condition:
    any of them
}