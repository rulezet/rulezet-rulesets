rule TTP_XOR_MULT_DOSStub_20a1 {
  strings:
    $key_20a1 = { 74 c9 [2] 00 d1 [2] 47 d3 [2] 00 c2 [2] 4e ce [2] 42 c4 [2] 55 cf [2] 4e 81 [2] 73 }

  condition:
    any of them
}