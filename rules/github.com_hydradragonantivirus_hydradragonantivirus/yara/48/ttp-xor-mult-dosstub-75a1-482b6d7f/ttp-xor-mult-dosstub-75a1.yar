rule TTP_XOR_MULT_DOSStub_75a1 {
  strings:
    $key_75a1 = { 21 c9 [2] 55 d1 [2] 12 d3 [2] 55 c2 [2] 1b ce [2] 17 c4 [2] 00 cf [2] 1b 81 [2] 26 }

  condition:
    any of them
}