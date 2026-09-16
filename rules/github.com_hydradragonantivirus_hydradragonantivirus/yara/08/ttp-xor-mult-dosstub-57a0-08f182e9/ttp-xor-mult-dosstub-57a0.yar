rule TTP_XOR_MULT_DOSStub_57a0 {
  strings:
    $key_57a0 = { 03 c8 [2] 77 d0 [2] 30 d2 [2] 77 c3 [2] 39 cf [2] 35 c5 [2] 22 ce [2] 39 80 [2] 04 }

  condition:
    any of them
}