rule TTP_XOR_MULT_DOSStub_74a6 {
  strings:
    $key_74a6 = { 20 ce [2] 54 d6 [2] 13 d4 [2] 54 c5 [2] 1a c9 [2] 16 c3 [2] 01 c8 [2] 1a 86 [2] 27 }

  condition:
    any of them
}