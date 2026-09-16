rule TTP_XOR_MULT_DOSStub_11a6 {
  strings:
    $key_11a6 = { 45 ce [2] 31 d6 [2] 76 d4 [2] 31 c5 [2] 7f c9 [2] 73 c3 [2] 64 c8 [2] 7f 86 [2] 42 }

  condition:
    any of them
}