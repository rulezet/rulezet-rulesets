rule TTP_XOR_MULT_DOSStub_96a7 {
  strings:
    $key_96a7 = { c2 cf [2] b6 d7 [2] f1 d5 [2] b6 c4 [2] f8 c8 [2] f4 c2 [2] e3 c9 [2] f8 87 [2] c5 }

  condition:
    any of them
}