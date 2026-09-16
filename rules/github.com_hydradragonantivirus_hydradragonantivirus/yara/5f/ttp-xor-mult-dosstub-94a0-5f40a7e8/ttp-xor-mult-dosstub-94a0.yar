rule TTP_XOR_MULT_DOSStub_94a0 {
  strings:
    $key_94a0 = { c0 c8 [2] b4 d0 [2] f3 d2 [2] b4 c3 [2] fa cf [2] f6 c5 [2] e1 ce [2] fa 80 [2] c7 }

  condition:
    any of them
}