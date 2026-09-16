rule TTP_XOR_MULT_DOSStub_97ac {
  strings:
    $key_97ac = { c3 c4 [2] b7 dc [2] f0 de [2] b7 cf [2] f9 c3 [2] f5 c9 [2] e2 c2 [2] f9 8c [2] c4 }

  condition:
    any of them
}