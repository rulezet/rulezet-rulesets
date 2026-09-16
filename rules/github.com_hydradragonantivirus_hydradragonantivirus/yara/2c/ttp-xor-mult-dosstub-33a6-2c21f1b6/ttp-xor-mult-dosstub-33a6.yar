rule TTP_XOR_MULT_DOSStub_33a6 {
  strings:
    $key_33a6 = { 67 ce [2] 13 d6 [2] 54 d4 [2] 13 c5 [2] 5d c9 [2] 51 c3 [2] 46 c8 [2] 5d 86 [2] 60 }

  condition:
    any of them
}