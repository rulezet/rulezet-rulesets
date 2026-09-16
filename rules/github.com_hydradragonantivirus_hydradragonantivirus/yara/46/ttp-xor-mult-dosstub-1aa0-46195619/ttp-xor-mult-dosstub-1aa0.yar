rule TTP_XOR_MULT_DOSStub_1aa0 {
  strings:
    $key_1aa0 = { 4e c8 [2] 3a d0 [2] 7d d2 [2] 3a c3 [2] 74 cf [2] 78 c5 [2] 6f ce [2] 74 80 [2] 49 }

  condition:
    any of them
}