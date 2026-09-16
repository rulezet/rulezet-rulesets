rule TTP_XOR_MULT_DOSStub_4da7 {
  strings:
    $key_4da7 = { 19 cf [2] 6d d7 [2] 2a d5 [2] 6d c4 [2] 23 c8 [2] 2f c2 [2] 38 c9 [2] 23 87 [2] 1e }

  condition:
    any of them
}