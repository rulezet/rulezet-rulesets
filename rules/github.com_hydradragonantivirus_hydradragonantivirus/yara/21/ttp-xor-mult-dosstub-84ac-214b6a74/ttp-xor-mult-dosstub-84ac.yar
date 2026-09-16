rule TTP_XOR_MULT_DOSStub_84ac {
  strings:
    $key_84ac = { d0 c4 [2] a4 dc [2] e3 de [2] a4 cf [2] ea c3 [2] e6 c9 [2] f1 c2 [2] ea 8c [2] d7 }

  condition:
    any of them
}