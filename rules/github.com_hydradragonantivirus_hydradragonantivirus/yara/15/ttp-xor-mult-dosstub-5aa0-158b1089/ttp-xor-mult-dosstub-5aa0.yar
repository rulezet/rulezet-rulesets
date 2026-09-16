rule TTP_XOR_MULT_DOSStub_5aa0 {
  strings:
    $key_5aa0 = { 0e c8 [2] 7a d0 [2] 3d d2 [2] 7a c3 [2] 34 cf [2] 38 c5 [2] 2f ce [2] 34 80 [2] 09 }

  condition:
    any of them
}