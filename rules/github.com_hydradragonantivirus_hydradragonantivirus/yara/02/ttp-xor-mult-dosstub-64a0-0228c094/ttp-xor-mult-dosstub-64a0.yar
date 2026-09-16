rule TTP_XOR_MULT_DOSStub_64a0 {
  strings:
    $key_64a0 = { 30 c8 [2] 44 d0 [2] 03 d2 [2] 44 c3 [2] 0a cf [2] 06 c5 [2] 11 ce [2] 0a 80 [2] 37 }

  condition:
    any of them
}