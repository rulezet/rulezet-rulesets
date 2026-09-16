rule TTP_XOR_MULT_DOSStub_37a1 {
  strings:
    $key_37a1 = { 63 c9 [2] 17 d1 [2] 50 d3 [2] 17 c2 [2] 59 ce [2] 55 c4 [2] 42 cf [2] 59 81 [2] 64 }

  condition:
    any of them
}