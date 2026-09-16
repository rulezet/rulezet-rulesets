rule TTP_XOR_MULT_DOSStub_9ba7 {
  strings:
    $key_9ba7 = { cf cf [2] bb d7 [2] fc d5 [2] bb c4 [2] f5 c8 [2] f9 c2 [2] ee c9 [2] f5 87 [2] c8 }

  condition:
    any of them
}