rule TTP_XOR_MULT_DOSStub_0da1 {
  strings:
    $key_0da1 = { 59 c9 [2] 2d d1 [2] 6a d3 [2] 2d c2 [2] 63 ce [2] 6f c4 [2] 78 cf [2] 63 81 [2] 5e }

  condition:
    any of them
}