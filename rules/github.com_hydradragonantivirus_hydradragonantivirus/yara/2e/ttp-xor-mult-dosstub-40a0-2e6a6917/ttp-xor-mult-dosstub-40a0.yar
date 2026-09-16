rule TTP_XOR_MULT_DOSStub_40a0 {
  strings:
    $key_40a0 = { 14 c8 [2] 60 d0 [2] 27 d2 [2] 60 c3 [2] 2e cf [2] 22 c5 [2] 35 ce [2] 2e 80 [2] 13 }

  condition:
    any of them
}