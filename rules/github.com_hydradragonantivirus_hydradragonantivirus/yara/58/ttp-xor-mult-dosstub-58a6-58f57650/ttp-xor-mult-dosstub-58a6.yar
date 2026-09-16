rule TTP_XOR_MULT_DOSStub_58a6 {
  strings:
    $key_58a6 = { 0c ce [2] 78 d6 [2] 3f d4 [2] 78 c5 [2] 36 c9 [2] 3a c3 [2] 2d c8 [2] 36 86 [2] 0b }

  condition:
    any of them
}