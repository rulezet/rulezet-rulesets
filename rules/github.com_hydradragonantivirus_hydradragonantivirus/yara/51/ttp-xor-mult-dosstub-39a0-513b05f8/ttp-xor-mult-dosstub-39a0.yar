rule TTP_XOR_MULT_DOSStub_39a0 {
  strings:
    $key_39a0 = { 6d c8 [2] 19 d0 [2] 5e d2 [2] 19 c3 [2] 57 cf [2] 5b c5 [2] 4c ce [2] 57 80 [2] 6a }

  condition:
    any of them
}