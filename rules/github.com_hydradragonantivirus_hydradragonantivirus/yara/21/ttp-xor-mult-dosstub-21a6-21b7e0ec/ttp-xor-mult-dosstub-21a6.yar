rule TTP_XOR_MULT_DOSStub_21a6 {
  strings:
    $key_21a6 = { 75 ce [2] 01 d6 [2] 46 d4 [2] 01 c5 [2] 4f c9 [2] 43 c3 [2] 54 c8 [2] 4f 86 [2] 72 }

  condition:
    any of them
}