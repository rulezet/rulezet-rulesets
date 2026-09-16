rule TTP_XOR_MULT_DOSStub_87a7 {
  strings:
    $key_87a7 = { d3 cf [2] a7 d7 [2] e0 d5 [2] a7 c4 [2] e9 c8 [2] e5 c2 [2] f2 c9 [2] e9 87 [2] d4 }

  condition:
    any of them
}