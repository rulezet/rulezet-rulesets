rule TTP_XOR_MULT_DOSStub_9ba1 {
  strings:
    $key_9ba1 = { cf c9 [2] bb d1 [2] fc d3 [2] bb c2 [2] f5 ce [2] f9 c4 [2] ee cf [2] f5 81 [2] c8 }

  condition:
    any of them
}