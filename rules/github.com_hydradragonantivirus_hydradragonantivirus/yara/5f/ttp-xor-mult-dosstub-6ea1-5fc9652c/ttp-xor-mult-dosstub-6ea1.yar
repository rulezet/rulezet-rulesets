rule TTP_XOR_MULT_DOSStub_6ea1 {
  strings:
    $key_6ea1 = { 3a c9 [2] 4e d1 [2] 09 d3 [2] 4e c2 [2] 00 ce [2] 0c c4 [2] 1b cf [2] 00 81 [2] 3d }

  condition:
    any of them
}