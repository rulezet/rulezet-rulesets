rule TTP_XOR_MULT_DOSStub_1fa7 {
  strings:
    $key_1fa7 = { 4b cf [2] 3f d7 [2] 78 d5 [2] 3f c4 [2] 71 c8 [2] 7d c2 [2] 6a c9 [2] 71 87 [2] 4c }

  condition:
    any of them
}