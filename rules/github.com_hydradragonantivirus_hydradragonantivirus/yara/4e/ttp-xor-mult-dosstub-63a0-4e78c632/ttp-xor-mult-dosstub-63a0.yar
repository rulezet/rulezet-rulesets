rule TTP_XOR_MULT_DOSStub_63a0 {
  strings:
    $key_63a0 = { 37 c8 [2] 43 d0 [2] 04 d2 [2] 43 c3 [2] 0d cf [2] 01 c5 [2] 16 ce [2] 0d 80 [2] 30 }

  condition:
    any of them
}