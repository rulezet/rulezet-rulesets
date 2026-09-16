rule TTP_XOR_MULT_DOSStub_84a7 {
  strings:
    $key_84a7 = { d0 cf [2] a4 d7 [2] e3 d5 [2] a4 c4 [2] ea c8 [2] e6 c2 [2] f1 c9 [2] ea 87 [2] d7 }

  condition:
    any of them
}