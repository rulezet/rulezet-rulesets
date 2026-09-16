rule TTP_XOR_MULT_DOSStub_26a6 {
  strings:
    $key_26a6 = { 72 ce [2] 06 d6 [2] 41 d4 [2] 06 c5 [2] 48 c9 [2] 44 c3 [2] 53 c8 [2] 48 86 [2] 75 }

  condition:
    any of them
}