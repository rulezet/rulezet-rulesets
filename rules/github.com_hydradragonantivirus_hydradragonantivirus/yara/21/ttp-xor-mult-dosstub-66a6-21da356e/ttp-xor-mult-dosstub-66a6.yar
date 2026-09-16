rule TTP_XOR_MULT_DOSStub_66a6 {
  strings:
    $key_66a6 = { 32 ce [2] 46 d6 [2] 01 d4 [2] 46 c5 [2] 08 c9 [2] 04 c3 [2] 13 c8 [2] 08 86 [2] 35 }

  condition:
    any of them
}