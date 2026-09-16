rule TTP_XOR_MULT_DOSStub_94a7 {
  strings:
    $key_94a7 = { c0 cf [2] b4 d7 [2] f3 d5 [2] b4 c4 [2] fa c8 [2] f6 c2 [2] e1 c9 [2] fa 87 [2] c7 }

  condition:
    any of them
}