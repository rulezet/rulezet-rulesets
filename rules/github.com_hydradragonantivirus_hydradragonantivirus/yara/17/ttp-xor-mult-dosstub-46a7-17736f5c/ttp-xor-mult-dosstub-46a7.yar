rule TTP_XOR_MULT_DOSStub_46a7 {
  strings:
    $key_46a7 = { 12 cf [2] 66 d7 [2] 21 d5 [2] 66 c4 [2] 28 c8 [2] 24 c2 [2] 33 c9 [2] 28 87 [2] 15 }

  condition:
    any of them
}