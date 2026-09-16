rule TTP_XOR_MULT_DOSStub_4aa1 {
  strings:
    $key_4aa1 = { 1e c9 [2] 6a d1 [2] 2d d3 [2] 6a c2 [2] 24 ce [2] 28 c4 [2] 3f cf [2] 24 81 [2] 19 }

  condition:
    any of them
}