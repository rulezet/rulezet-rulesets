rule TTP_XOR_MULT_DOSStub_73a1 {
  strings:
    $key_73a1 = { 27 c9 [2] 53 d1 [2] 14 d3 [2] 53 c2 [2] 1d ce [2] 11 c4 [2] 06 cf [2] 1d 81 [2] 20 }

  condition:
    any of them
}