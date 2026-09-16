rule TTP_XOR_MULT_DOSStub_4da0 {
  strings:
    $key_4da0 = { 19 c8 [2] 6d d0 [2] 2a d2 [2] 6d c3 [2] 23 cf [2] 2f c5 [2] 38 ce [2] 23 80 [2] 1e }

  condition:
    any of them
}