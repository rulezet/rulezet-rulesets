rule TTP_XOR_MULT_DOSStub_35a1 {
  strings:
    $key_35a1 = { 61 c9 [2] 15 d1 [2] 52 d3 [2] 15 c2 [2] 5b ce [2] 57 c4 [2] 40 cf [2] 5b 81 [2] 66 }

  condition:
    any of them
}