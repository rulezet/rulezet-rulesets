rule TTP_XOR_MULT_DOSStub_94ac {
  strings:
    $key_94ac = { c0 c4 [2] b4 dc [2] f3 de [2] b4 cf [2] fa c3 [2] f6 c9 [2] e1 c2 [2] fa 8c [2] c7 }

  condition:
    any of them
}