rule TTP_XOR_MULT_DOSStub_97a7 {
  strings:
    $key_97a7 = { c3 cf [2] b7 d7 [2] f0 d5 [2] b7 c4 [2] f9 c8 [2] f5 c2 [2] e2 c9 [2] f9 87 [2] c4 }

  condition:
    any of them
}