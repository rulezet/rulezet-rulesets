rule TTP_XOR_MULT_DOSStub_48a0 {
  strings:
    $key_48a0 = { 1c c8 [2] 68 d0 [2] 2f d2 [2] 68 c3 [2] 26 cf [2] 2a c5 [2] 3d ce [2] 26 80 [2] 1b }

  condition:
    any of them
}