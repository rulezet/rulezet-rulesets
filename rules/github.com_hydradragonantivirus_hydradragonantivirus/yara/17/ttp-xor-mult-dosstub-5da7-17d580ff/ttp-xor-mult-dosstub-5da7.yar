rule TTP_XOR_MULT_DOSStub_5da7 {
  strings:
    $key_5da7 = { 09 cf [2] 7d d7 [2] 3a d5 [2] 7d c4 [2] 33 c8 [2] 3f c2 [2] 28 c9 [2] 33 87 [2] 0e }

  condition:
    any of them
}