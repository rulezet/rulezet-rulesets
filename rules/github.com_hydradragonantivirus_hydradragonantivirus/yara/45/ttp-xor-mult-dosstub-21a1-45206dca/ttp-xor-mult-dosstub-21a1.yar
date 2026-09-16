rule TTP_XOR_MULT_DOSStub_21a1 {
  strings:
    $key_21a1 = { 75 c9 [2] 01 d1 [2] 46 d3 [2] 01 c2 [2] 4f ce [2] 43 c4 [2] 54 cf [2] 4f 81 [2] 72 }

  condition:
    any of them
}