rule TTP_XOR_MULT_DOSStub_48a6 {
  strings:
    $key_48a6 = { 1c ce [2] 68 d6 [2] 2f d4 [2] 68 c5 [2] 26 c9 [2] 2a c3 [2] 3d c8 [2] 26 86 [2] 1b }

  condition:
    any of them
}