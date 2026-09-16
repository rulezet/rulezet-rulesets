rule TTP_XOR_MULT_DOSStub_57a1 {
  strings:
    $key_57a1 = { 03 c9 [2] 77 d1 [2] 30 d3 [2] 77 c2 [2] 39 ce [2] 35 c4 [2] 22 cf [2] 39 81 [2] 04 }

  condition:
    any of them
}