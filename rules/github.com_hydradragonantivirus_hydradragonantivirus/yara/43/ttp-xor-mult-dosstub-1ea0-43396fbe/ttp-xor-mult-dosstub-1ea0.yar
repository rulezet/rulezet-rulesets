rule TTP_XOR_MULT_DOSStub_1ea0 {
  strings:
    $key_1ea0 = { 4a c8 [2] 3e d0 [2] 79 d2 [2] 3e c3 [2] 70 cf [2] 7c c5 [2] 6b ce [2] 70 80 [2] 4d }

  condition:
    any of them
}