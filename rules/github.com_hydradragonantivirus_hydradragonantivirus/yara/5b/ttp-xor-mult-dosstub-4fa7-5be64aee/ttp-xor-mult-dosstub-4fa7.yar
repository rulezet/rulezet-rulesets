rule TTP_XOR_MULT_DOSStub_4fa7 {
  strings:
    $key_4fa7 = { 1b cf [2] 6f d7 [2] 28 d5 [2] 6f c4 [2] 21 c8 [2] 2d c2 [2] 3a c9 [2] 21 87 [2] 1c }

  condition:
    any of them
}