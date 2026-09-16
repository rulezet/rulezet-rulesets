rule TTP_XOR_MULT_DOSStub_58a0 {
  strings:
    $key_58a0 = { 0c c8 [2] 78 d0 [2] 3f d2 [2] 78 c3 [2] 36 cf [2] 3a c5 [2] 2d ce [2] 36 80 [2] 0b }

  condition:
    any of them
}