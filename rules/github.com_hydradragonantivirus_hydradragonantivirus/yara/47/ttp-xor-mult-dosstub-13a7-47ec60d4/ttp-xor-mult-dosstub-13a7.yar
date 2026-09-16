rule TTP_XOR_MULT_DOSStub_13a7 {
  strings:
    $key_13a7 = { 47 cf [2] 33 d7 [2] 74 d5 [2] 33 c4 [2] 7d c8 [2] 71 c2 [2] 66 c9 [2] 7d 87 [2] 40 }

  condition:
    any of them
}