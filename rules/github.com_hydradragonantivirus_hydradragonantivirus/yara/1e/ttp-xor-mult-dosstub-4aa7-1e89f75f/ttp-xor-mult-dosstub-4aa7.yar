rule TTP_XOR_MULT_DOSStub_4aa7 {
  strings:
    $key_4aa7 = { 1e cf [2] 6a d7 [2] 2d d5 [2] 6a c4 [2] 24 c8 [2] 28 c2 [2] 3f c9 [2] 24 87 [2] 19 }

  condition:
    any of them
}