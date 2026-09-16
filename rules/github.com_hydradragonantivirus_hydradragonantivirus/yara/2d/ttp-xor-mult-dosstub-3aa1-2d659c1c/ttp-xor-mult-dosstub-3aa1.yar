rule TTP_XOR_MULT_DOSStub_3aa1 {
  strings:
    $key_3aa1 = { 6e c9 [2] 1a d1 [2] 5d d3 [2] 1a c2 [2] 54 ce [2] 58 c4 [2] 4f cf [2] 54 81 [2] 69 }

  condition:
    any of them
}