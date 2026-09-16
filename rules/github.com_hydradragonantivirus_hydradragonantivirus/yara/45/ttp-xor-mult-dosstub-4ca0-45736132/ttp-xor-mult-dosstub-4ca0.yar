rule TTP_XOR_MULT_DOSStub_4ca0 {
  strings:
    $key_4ca0 = { 18 c8 [2] 6c d0 [2] 2b d2 [2] 6c c3 [2] 22 cf [2] 2e c5 [2] 39 ce [2] 22 80 [2] 1f }

  condition:
    any of them
}