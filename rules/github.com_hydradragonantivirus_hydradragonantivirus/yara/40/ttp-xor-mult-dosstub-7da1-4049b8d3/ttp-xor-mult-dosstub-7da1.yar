rule TTP_XOR_MULT_DOSStub_7da1 {
  strings:
    $key_7da1 = { 29 c9 [2] 5d d1 [2] 1a d3 [2] 5d c2 [2] 13 ce [2] 1f c4 [2] 08 cf [2] 13 81 [2] 2e }

  condition:
    any of them
}