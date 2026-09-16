rule TTP_XOR_MULT_DOSStub_d4a1 {
  strings:
    $key_d4a1 = { 80 c9 [2] f4 d1 [2] b3 d3 [2] f4 c2 [2] ba ce [2] b6 c4 [2] a1 cf [2] ba 81 [2] 87 }

  condition:
    any of them
}