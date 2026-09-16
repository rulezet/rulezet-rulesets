rule TTP_XOR_MULT_DOSStub_57a6 {
  strings:
    $key_57a6 = { 03 ce [2] 77 d6 [2] 30 d4 [2] 77 c5 [2] 39 c9 [2] 35 c3 [2] 22 c8 [2] 39 86 [2] 04 }

  condition:
    any of them
}