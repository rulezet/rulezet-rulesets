rule TTP_XOR_MULT_DOSStub_3aa0 {
  strings:
    $key_3aa0 = { 6e c8 [2] 1a d0 [2] 5d d2 [2] 1a c3 [2] 54 cf [2] 58 c5 [2] 4f ce [2] 54 80 [2] 69 }

  condition:
    any of them
}