rule TTP_XOR_MULT_DOSStub_42a6 {
  strings:
    $key_42a6 = { 16 ce [2] 62 d6 [2] 25 d4 [2] 62 c5 [2] 2c c9 [2] 20 c3 [2] 37 c8 [2] 2c 86 [2] 11 }

  condition:
    any of them
}