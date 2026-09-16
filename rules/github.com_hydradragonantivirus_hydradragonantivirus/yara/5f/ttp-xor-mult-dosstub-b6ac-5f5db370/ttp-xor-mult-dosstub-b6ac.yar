rule TTP_XOR_MULT_DOSStub_b6ac {
  strings:
    $key_b6ac = { e2 c4 [2] 96 dc [2] d1 de [2] 96 cf [2] d8 c3 [2] d4 c9 [2] c3 c2 [2] d8 8c [2] e5 }

  condition:
    any of them
}