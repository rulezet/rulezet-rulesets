rule TTP_XOR_MULT_DOSStub_60a0 {
  strings:
    $key_60a0 = { 34 c8 [2] 40 d0 [2] 07 d2 [2] 40 c3 [2] 0e cf [2] 02 c5 [2] 15 ce [2] 0e 80 [2] 33 }

  condition:
    any of them
}