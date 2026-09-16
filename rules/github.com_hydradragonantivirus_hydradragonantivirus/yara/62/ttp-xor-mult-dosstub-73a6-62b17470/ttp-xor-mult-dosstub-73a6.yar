rule TTP_XOR_MULT_DOSStub_73a6 {
  strings:
    $key_73a6 = { 27 ce [2] 53 d6 [2] 14 d4 [2] 53 c5 [2] 1d c9 [2] 11 c3 [2] 06 c8 [2] 1d 86 [2] 20 }

  condition:
    any of them
}