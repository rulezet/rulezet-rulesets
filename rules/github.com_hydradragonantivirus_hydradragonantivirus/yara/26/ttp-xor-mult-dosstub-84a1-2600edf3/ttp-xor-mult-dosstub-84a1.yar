rule TTP_XOR_MULT_DOSStub_84a1 {
  strings:
    $key_84a1 = { d0 c9 [2] a4 d1 [2] e3 d3 [2] a4 c2 [2] ea ce [2] e6 c4 [2] f1 cf [2] ea 81 [2] d7 }

  condition:
    any of them
}