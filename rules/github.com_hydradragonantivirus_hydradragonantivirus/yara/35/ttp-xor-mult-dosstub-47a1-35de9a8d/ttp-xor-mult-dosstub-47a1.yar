rule TTP_XOR_MULT_DOSStub_47a1 {
  strings:
    $key_47a1 = { 13 c9 [2] 67 d1 [2] 20 d3 [2] 67 c2 [2] 29 ce [2] 25 c4 [2] 32 cf [2] 29 81 [2] 14 }

  condition:
    any of them
}