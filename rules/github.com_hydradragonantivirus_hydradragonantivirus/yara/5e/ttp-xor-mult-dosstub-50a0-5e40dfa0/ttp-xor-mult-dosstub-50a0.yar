rule TTP_XOR_MULT_DOSStub_50a0 {
  strings:
    $key_50a0 = { 04 c8 [2] 70 d0 [2] 37 d2 [2] 70 c3 [2] 3e cf [2] 32 c5 [2] 25 ce [2] 3e 80 [2] 03 }

  condition:
    any of them
}