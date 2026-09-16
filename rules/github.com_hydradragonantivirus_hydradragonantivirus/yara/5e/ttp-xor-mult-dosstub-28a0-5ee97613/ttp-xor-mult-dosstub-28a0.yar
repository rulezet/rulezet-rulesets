rule TTP_XOR_MULT_DOSStub_28a0 {
  strings:
    $key_28a0 = { 7c c8 [2] 08 d0 [2] 4f d2 [2] 08 c3 [2] 46 cf [2] 4a c5 [2] 5d ce [2] 46 80 [2] 7b }

  condition:
    any of them
}