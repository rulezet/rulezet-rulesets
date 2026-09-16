rule TTP_XOR_MULT_DOSStub_41a7 {
  strings:
    $key_41a7 = { 15 cf [2] 61 d7 [2] 26 d5 [2] 61 c4 [2] 2f c8 [2] 23 c2 [2] 34 c9 [2] 2f 87 [2] 12 }

  condition:
    any of them
}