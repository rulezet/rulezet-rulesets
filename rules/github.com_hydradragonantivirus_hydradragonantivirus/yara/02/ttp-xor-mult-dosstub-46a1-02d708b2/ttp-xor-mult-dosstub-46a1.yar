rule TTP_XOR_MULT_DOSStub_46a1 {
  strings:
    $key_46a1 = { 12 c9 [2] 66 d1 [2] 21 d3 [2] 66 c2 [2] 28 ce [2] 24 c4 [2] 33 cf [2] 28 81 [2] 15 }

  condition:
    any of them
}