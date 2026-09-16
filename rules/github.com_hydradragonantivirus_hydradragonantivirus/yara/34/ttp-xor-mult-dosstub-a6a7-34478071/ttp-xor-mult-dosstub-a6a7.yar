rule TTP_XOR_MULT_DOSStub_a6a7 {
  strings:
    $key_a6a7 = { f2 cf [2] 86 d7 [2] c1 d5 [2] 86 c4 [2] c8 c8 [2] c4 c2 [2] d3 c9 [2] c8 87 [2] f5 }

  condition:
    any of them
}