rule TTP_XOR_MULT_DOSStub_22a7 {
  strings:
    $key_22a7 = { 76 cf [2] 02 d7 [2] 45 d5 [2] 02 c4 [2] 4c c8 [2] 40 c2 [2] 57 c9 [2] 4c 87 [2] 71 }

  condition:
    any of them
}