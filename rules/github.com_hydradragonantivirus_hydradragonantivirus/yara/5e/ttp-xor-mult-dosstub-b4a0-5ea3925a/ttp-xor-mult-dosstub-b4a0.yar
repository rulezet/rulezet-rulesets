rule TTP_XOR_MULT_DOSStub_b4a0 {
  strings:
    $key_b4a0 = { e0 c8 [2] 94 d0 [2] d3 d2 [2] 94 c3 [2] da cf [2] d6 c5 [2] c1 ce [2] da 80 [2] e7 }

  condition:
    any of them
}