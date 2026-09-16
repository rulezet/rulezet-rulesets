rule TTP_XOR_MULT_DOSStub_09a0 {
  strings:
    $key_09a0 = { 5d c8 [2] 29 d0 [2] 6e d2 [2] 29 c3 [2] 67 cf [2] 6b c5 [2] 7c ce [2] 67 80 [2] 5a }

  condition:
    any of them
}