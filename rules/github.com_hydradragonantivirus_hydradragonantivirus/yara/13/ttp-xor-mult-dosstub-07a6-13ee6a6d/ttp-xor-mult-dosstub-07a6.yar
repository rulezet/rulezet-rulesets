rule TTP_XOR_MULT_DOSStub_07a6 {
  strings:
    $key_07a6 = { 53 ce [2] 27 d6 [2] 60 d4 [2] 27 c5 [2] 69 c9 [2] 65 c3 [2] 72 c8 [2] 69 86 [2] 54 }

  condition:
    any of them
}