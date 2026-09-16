rule TTP_XOR_MULT_DOSStub_7ea0 {
  strings:
    $key_7ea0 = { 2a c8 [2] 5e d0 [2] 19 d2 [2] 5e c3 [2] 10 cf [2] 1c c5 [2] 0b ce [2] 10 80 [2] 2d }

  condition:
    any of them
}