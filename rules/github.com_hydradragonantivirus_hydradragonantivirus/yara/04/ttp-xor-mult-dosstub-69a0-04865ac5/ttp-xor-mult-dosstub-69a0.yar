rule TTP_XOR_MULT_DOSStub_69a0 {
  strings:
    $key_69a0 = { 3d c8 [2] 49 d0 [2] 0e d2 [2] 49 c3 [2] 07 cf [2] 0b c5 [2] 1c ce [2] 07 80 [2] 3a }

  condition:
    any of them
}