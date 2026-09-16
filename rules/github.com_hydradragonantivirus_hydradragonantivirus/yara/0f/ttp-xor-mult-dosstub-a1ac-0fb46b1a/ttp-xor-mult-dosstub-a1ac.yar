rule TTP_XOR_MULT_DOSStub_a1ac {
  strings:
    $key_a1ac = { f5 c4 [2] 81 dc [2] c6 de [2] 81 cf [2] cf c3 [2] c3 c9 [2] d4 c2 [2] cf 8c [2] f2 }

  condition:
    any of them
}