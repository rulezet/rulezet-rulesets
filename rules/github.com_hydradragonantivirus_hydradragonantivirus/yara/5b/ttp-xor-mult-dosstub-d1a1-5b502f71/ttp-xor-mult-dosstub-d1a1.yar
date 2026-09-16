rule TTP_XOR_MULT_DOSStub_d1a1 {
  strings:
    $key_d1a1 = { 85 c9 [2] f1 d1 [2] b6 d3 [2] f1 c2 [2] bf ce [2] b3 c4 [2] a4 cf [2] bf 81 [2] 82 }

  condition:
    any of them
}