rule TTP_XOR_MULT_DOSStub_18a0 {
  strings:
    $key_18a0 = { 4c c8 [2] 38 d0 [2] 7f d2 [2] 38 c3 [2] 76 cf [2] 7a c5 [2] 6d ce [2] 76 80 [2] 4b }

  condition:
    any of them
}