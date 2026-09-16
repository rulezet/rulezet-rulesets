rule TTP_XOR_MULT_DOSStub_0ca0 {
  strings:
    $key_0ca0 = { 58 c8 [2] 2c d0 [2] 6b d2 [2] 2c c3 [2] 62 cf [2] 6e c5 [2] 79 ce [2] 62 80 [2] 5f }

  condition:
    any of them
}