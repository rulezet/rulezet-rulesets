rule TTP_XOR_MULT_DOSStub_20a0 {
  strings:
    $key_20a0 = { 74 c8 [2] 00 d0 [2] 47 d2 [2] 00 c3 [2] 4e cf [2] 42 c5 [2] 55 ce [2] 4e 80 [2] 73 }

  condition:
    any of them
}