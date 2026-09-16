rule TTP_XOR_MULT_DOSStub_6ca0 {
  strings:
    $key_6ca0 = { 38 c8 [2] 4c d0 [2] 0b d2 [2] 4c c3 [2] 02 cf [2] 0e c5 [2] 19 ce [2] 02 80 [2] 3f }

  condition:
    any of them
}