rule TTP_XOR_MULT_DOSStub_86ac {
  strings:
    $key_86ac = { d2 c4 [2] a6 dc [2] e1 de [2] a6 cf [2] e8 c3 [2] e4 c9 [2] f3 c2 [2] e8 8c [2] d5 }

  condition:
    any of them
}