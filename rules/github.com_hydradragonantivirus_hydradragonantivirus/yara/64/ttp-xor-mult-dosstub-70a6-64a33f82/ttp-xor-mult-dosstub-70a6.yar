rule TTP_XOR_MULT_DOSStub_70a6 {
  strings:
    $key_70a6 = { 24 ce [2] 50 d6 [2] 17 d4 [2] 50 c5 [2] 1e c9 [2] 12 c3 [2] 05 c8 [2] 1e 86 [2] 23 }

  condition:
    any of them
}