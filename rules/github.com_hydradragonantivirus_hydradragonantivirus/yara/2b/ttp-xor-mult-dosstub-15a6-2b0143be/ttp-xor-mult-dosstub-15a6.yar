rule TTP_XOR_MULT_DOSStub_15a6 {
  strings:
    $key_15a6 = { 41 ce [2] 35 d6 [2] 72 d4 [2] 35 c5 [2] 7b c9 [2] 77 c3 [2] 60 c8 [2] 7b 86 [2] 46 }

  condition:
    any of them
}