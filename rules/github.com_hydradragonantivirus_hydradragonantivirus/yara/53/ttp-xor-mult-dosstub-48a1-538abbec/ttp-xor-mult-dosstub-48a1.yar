rule TTP_XOR_MULT_DOSStub_48a1 {
  strings:
    $key_48a1 = { 1c c9 [2] 68 d1 [2] 2f d3 [2] 68 c2 [2] 26 ce [2] 2a c4 [2] 3d cf [2] 26 81 [2] 1b }

  condition:
    any of them
}