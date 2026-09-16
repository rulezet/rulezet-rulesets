rule TTP_XOR_MULT_DOSStub_3ca0 {
  strings:
    $key_3ca0 = { 68 c8 [2] 1c d0 [2] 5b d2 [2] 1c c3 [2] 52 cf [2] 5e c5 [2] 49 ce [2] 52 80 [2] 6f }

  condition:
    any of them
}