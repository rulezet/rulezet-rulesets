rule TTP_XOR_MULT_DOSStub_03a0 {
  strings:
    $key_03a0 = { 57 c8 [2] 23 d0 [2] 64 d2 [2] 23 c3 [2] 6d cf [2] 61 c5 [2] 76 ce [2] 6d 80 [2] 50 }

  condition:
    any of them
}