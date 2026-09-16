rule TTP_XOR_MULT_DOSStub_b2a1 {
  strings:
    $key_b2a1 = { e6 c9 [2] 92 d1 [2] d5 d3 [2] 92 c2 [2] dc ce [2] d0 c4 [2] c7 cf [2] dc 81 [2] e1 }

  condition:
    any of them
}