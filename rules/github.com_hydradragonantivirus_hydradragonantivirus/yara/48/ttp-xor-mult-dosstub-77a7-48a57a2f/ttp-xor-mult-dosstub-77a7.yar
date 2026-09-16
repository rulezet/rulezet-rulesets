rule TTP_XOR_MULT_DOSStub_77a7 {
  strings:
    $key_77a7 = { 23 cf [2] 57 d7 [2] 10 d5 [2] 57 c4 [2] 19 c8 [2] 15 c2 [2] 02 c9 [2] 19 87 [2] 24 }

  condition:
    any of them
}