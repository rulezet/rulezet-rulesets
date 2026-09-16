rule TTP_XOR_MULT_DOSStub_23a6 {
  strings:
    $key_23a6 = { 77 ce [2] 03 d6 [2] 44 d4 [2] 03 c5 [2] 4d c9 [2] 41 c3 [2] 56 c8 [2] 4d 86 [2] 70 }

  condition:
    any of them
}