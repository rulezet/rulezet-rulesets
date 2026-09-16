rule TTP_XOR_MULT_DOSStub_44a1 {
  strings:
    $key_44a1 = { 10 c9 [2] 64 d1 [2] 23 d3 [2] 64 c2 [2] 2a ce [2] 26 c4 [2] 31 cf [2] 2a 81 [2] 17 }

  condition:
    any of them
}