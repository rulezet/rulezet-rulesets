rule TTP_XOR_MULT_DOSStub_66a1 {
  strings:
    $key_66a1 = { 32 c9 [2] 46 d1 [2] 01 d3 [2] 46 c2 [2] 08 ce [2] 04 c4 [2] 13 cf [2] 08 81 [2] 35 }

  condition:
    any of them
}