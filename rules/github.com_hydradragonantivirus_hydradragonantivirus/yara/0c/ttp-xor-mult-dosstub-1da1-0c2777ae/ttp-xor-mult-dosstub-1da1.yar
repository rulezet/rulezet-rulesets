rule TTP_XOR_MULT_DOSStub_1da1 {
  strings:
    $key_1da1 = { 49 c9 [2] 3d d1 [2] 7a d3 [2] 3d c2 [2] 73 ce [2] 7f c4 [2] 68 cf [2] 73 81 [2] 4e }

  condition:
    any of them
}