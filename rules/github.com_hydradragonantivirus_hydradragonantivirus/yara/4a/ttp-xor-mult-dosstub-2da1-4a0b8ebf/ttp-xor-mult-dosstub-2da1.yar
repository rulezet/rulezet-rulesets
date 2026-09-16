rule TTP_XOR_MULT_DOSStub_2da1 {
  strings:
    $key_2da1 = { 79 c9 [2] 0d d1 [2] 4a d3 [2] 0d c2 [2] 43 ce [2] 4f c4 [2] 58 cf [2] 43 81 [2] 7e }

  condition:
    any of them
}