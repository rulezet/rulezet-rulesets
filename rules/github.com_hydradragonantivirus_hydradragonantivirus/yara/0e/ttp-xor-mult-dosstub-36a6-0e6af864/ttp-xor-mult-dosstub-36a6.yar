rule TTP_XOR_MULT_DOSStub_36a6 {
  strings:
    $key_36a6 = { 62 ce [2] 16 d6 [2] 51 d4 [2] 16 c5 [2] 58 c9 [2] 54 c3 [2] 43 c8 [2] 58 86 [2] 65 }

  condition:
    any of them
}