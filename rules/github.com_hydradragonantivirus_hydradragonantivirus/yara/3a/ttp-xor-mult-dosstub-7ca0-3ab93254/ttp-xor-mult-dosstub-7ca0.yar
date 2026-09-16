rule TTP_XOR_MULT_DOSStub_7ca0 {
  strings:
    $key_7ca0 = { 28 c8 [2] 5c d0 [2] 1b d2 [2] 5c c3 [2] 12 cf [2] 1e c5 [2] 09 ce [2] 12 80 [2] 2f }

  condition:
    any of them
}