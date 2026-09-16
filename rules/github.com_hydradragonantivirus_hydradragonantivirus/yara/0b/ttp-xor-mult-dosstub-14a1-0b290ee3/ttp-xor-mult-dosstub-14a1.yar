rule TTP_XOR_MULT_DOSStub_14a1 {
  strings:
    $key_14a1 = { 40 c9 [2] 34 d1 [2] 73 d3 [2] 34 c2 [2] 7a ce [2] 76 c4 [2] 61 cf [2] 7a 81 [2] 47 }

  condition:
    any of them
}