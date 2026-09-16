rule TTP_XOR_MULT_DOSStub_50a7 {
  strings:
    $key_50a7 = { 04 cf [2] 70 d7 [2] 37 d5 [2] 70 c4 [2] 3e c8 [2] 32 c2 [2] 25 c9 [2] 3e 87 [2] 03 }

  condition:
    any of them
}