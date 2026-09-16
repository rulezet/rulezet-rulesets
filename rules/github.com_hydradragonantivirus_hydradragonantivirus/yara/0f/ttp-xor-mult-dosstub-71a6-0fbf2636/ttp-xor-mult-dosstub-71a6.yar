rule TTP_XOR_MULT_DOSStub_71a6 {
  strings:
    $key_71a6 = { 25 ce [2] 51 d6 [2] 16 d4 [2] 51 c5 [2] 1f c9 [2] 13 c3 [2] 04 c8 [2] 1f 86 [2] 22 }

  condition:
    any of them
}