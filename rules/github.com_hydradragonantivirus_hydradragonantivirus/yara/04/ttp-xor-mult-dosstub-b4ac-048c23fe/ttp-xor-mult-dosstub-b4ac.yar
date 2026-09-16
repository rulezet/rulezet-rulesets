rule TTP_XOR_MULT_DOSStub_b4ac {
  strings:
    $key_b4ac = { e0 c4 [2] 94 dc [2] d3 de [2] 94 cf [2] da c3 [2] d6 c9 [2] c1 c2 [2] da 8c [2] e7 }

  condition:
    any of them
}