rule TTP_XOR_MULT_DOSStub_7ca1 {
  strings:
    $key_7ca1 = { 28 c9 [2] 5c d1 [2] 1b d3 [2] 5c c2 [2] 12 ce [2] 1e c4 [2] 09 cf [2] 12 81 [2] 2f }

  condition:
    any of them
}