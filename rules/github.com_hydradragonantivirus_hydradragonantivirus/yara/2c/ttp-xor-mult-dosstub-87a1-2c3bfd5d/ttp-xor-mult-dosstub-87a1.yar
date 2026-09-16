rule TTP_XOR_MULT_DOSStub_87a1 {
  strings:
    $key_87a1 = { d3 c9 [2] a7 d1 [2] e0 d3 [2] a7 c2 [2] e9 ce [2] e5 c4 [2] f2 cf [2] e9 81 [2] d4 }

  condition:
    any of them
}