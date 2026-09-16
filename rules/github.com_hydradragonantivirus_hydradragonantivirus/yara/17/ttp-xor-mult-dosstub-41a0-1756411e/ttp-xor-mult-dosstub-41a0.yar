rule TTP_XOR_MULT_DOSStub_41a0 {
  strings:
    $key_41a0 = { 15 c8 [2] 61 d0 [2] 26 d2 [2] 61 c3 [2] 2f cf [2] 23 c5 [2] 34 ce [2] 2f 80 [2] 12 }

  condition:
    any of them
}