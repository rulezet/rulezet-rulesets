rule TTP_XOR_MULT_DOSStub_01a1 {
  strings:
    $key_01a1 = { 55 c9 [2] 21 d1 [2] 66 d3 [2] 21 c2 [2] 6f ce [2] 63 c4 [2] 74 cf [2] 6f 81 [2] 52 }

  condition:
    any of them
}