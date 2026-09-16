rule TTP_XOR_MULT_DOSStub_7aa0 {
  strings:
    $key_7aa0 = { 2e c8 [2] 5a d0 [2] 1d d2 [2] 5a c3 [2] 14 cf [2] 18 c5 [2] 0f ce [2] 14 80 [2] 29 }

  condition:
    any of them
}