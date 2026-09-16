rule TTP_XOR_MULT_DOSStub_83a7 {
  strings:
    $key_83a7 = { d7 cf [2] a3 d7 [2] e4 d5 [2] a3 c4 [2] ed c8 [2] e1 c2 [2] f6 c9 [2] ed 87 [2] d0 }

  condition:
    any of them
}