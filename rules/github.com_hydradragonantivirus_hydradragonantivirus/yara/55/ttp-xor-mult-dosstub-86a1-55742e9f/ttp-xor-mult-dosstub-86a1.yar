rule TTP_XOR_MULT_DOSStub_86a1 {
  strings:
    $key_86a1 = { d2 c9 [2] a6 d1 [2] e1 d3 [2] a6 c2 [2] e8 ce [2] e4 c4 [2] f3 cf [2] e8 81 [2] d5 }

  condition:
    any of them
}