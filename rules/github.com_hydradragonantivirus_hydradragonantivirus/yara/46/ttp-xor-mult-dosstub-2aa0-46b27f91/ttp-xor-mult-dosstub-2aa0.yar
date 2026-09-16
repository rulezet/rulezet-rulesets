rule TTP_XOR_MULT_DOSStub_2aa0 {
  strings:
    $key_2aa0 = { 7e c8 [2] 0a d0 [2] 4d d2 [2] 0a c3 [2] 44 cf [2] 48 c5 [2] 5f ce [2] 44 80 [2] 79 }

  condition:
    any of them
}