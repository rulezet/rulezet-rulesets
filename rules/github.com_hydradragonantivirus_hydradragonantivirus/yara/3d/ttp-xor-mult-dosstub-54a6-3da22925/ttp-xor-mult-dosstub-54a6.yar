rule TTP_XOR_MULT_DOSStub_54a6 {
  strings:
    $key_54a6 = { 00 ce [2] 74 d6 [2] 33 d4 [2] 74 c5 [2] 3a c9 [2] 36 c3 [2] 21 c8 [2] 3a 86 [2] 07 }

  condition:
    any of them
}