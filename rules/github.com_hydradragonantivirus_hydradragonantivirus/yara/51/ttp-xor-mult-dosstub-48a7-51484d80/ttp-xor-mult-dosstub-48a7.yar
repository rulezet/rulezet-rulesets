rule TTP_XOR_MULT_DOSStub_48a7 {
  strings:
    $key_48a7 = { 1c cf [2] 68 d7 [2] 2f d5 [2] 68 c4 [2] 26 c8 [2] 2a c2 [2] 3d c9 [2] 26 87 [2] 1b }

  condition:
    any of them
}