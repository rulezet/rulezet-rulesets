rule TTP_XOR_MULT_DOSStub_d7a1 {
  strings:
    $key_d7a1 = { 83 c9 [2] f7 d1 [2] b0 d3 [2] f7 c2 [2] b9 ce [2] b5 c4 [2] a2 cf [2] b9 81 [2] 84 }

  condition:
    any of them
}