rule TTP_XOR_MULT_DOSStub_a0a1 {
  strings:
    $key_a0a1 = { f4 c9 [2] 80 d1 [2] c7 d3 [2] 80 c2 [2] ce ce [2] c2 c4 [2] d5 cf [2] ce 81 [2] f3 }

  condition:
    any of them
}