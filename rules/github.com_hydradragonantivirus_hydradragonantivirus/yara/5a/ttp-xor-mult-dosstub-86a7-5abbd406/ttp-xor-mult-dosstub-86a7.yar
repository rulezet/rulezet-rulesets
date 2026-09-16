rule TTP_XOR_MULT_DOSStub_86a7 {
  strings:
    $key_86a7 = { d2 cf [2] a6 d7 [2] e1 d5 [2] a6 c4 [2] e8 c8 [2] e4 c2 [2] f3 c9 [2] e8 87 [2] d5 }

  condition:
    any of them
}