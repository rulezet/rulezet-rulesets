rule TTP_XOR_MULT_DOSStub_58a7 {
  strings:
    $key_58a7 = { 0c cf [2] 78 d7 [2] 3f d5 [2] 78 c4 [2] 36 c8 [2] 3a c2 [2] 2d c9 [2] 36 87 [2] 0b }

  condition:
    any of them
}