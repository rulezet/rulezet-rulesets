rule TTP_XOR_MULT_DOSStub_23a0 {
  strings:
    $key_23a0 = { 77 c8 [2] 03 d0 [2] 44 d2 [2] 03 c3 [2] 4d cf [2] 41 c5 [2] 56 ce [2] 4d 80 [2] 70 }

  condition:
    any of them
}