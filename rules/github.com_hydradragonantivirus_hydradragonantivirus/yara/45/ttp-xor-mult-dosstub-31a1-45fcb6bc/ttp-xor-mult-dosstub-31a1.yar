rule TTP_XOR_MULT_DOSStub_31a1 {
  strings:
    $key_31a1 = { 65 c9 [2] 11 d1 [2] 56 d3 [2] 11 c2 [2] 5f ce [2] 53 c4 [2] 44 cf [2] 5f 81 [2] 62 }

  condition:
    any of them
}