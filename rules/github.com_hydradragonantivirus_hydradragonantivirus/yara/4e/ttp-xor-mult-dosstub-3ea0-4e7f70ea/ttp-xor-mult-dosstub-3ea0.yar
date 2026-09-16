rule TTP_XOR_MULT_DOSStub_3ea0 {
  strings:
    $key_3ea0 = { 6a c8 [2] 1e d0 [2] 59 d2 [2] 1e c3 [2] 50 cf [2] 5c c5 [2] 4b ce [2] 50 80 [2] 6d }

  condition:
    any of them
}