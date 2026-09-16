rule TTP_XOR_MULT_DOSStub_67a6 {
  strings:
    $key_67a6 = { 33 ce [2] 47 d6 [2] 00 d4 [2] 47 c5 [2] 09 c9 [2] 05 c3 [2] 12 c8 [2] 09 86 [2] 34 }

  condition:
    any of them
}