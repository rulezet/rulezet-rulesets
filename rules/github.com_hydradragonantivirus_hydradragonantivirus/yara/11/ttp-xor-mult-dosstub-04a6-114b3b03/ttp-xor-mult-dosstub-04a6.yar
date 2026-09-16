rule TTP_XOR_MULT_DOSStub_04a6 {
  strings:
    $key_04a6 = { 50 ce [2] 24 d6 [2] 63 d4 [2] 24 c5 [2] 6a c9 [2] 66 c3 [2] 71 c8 [2] 6a 86 [2] 57 }

  condition:
    any of them
}