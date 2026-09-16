rule TTP_XOR_MULT_DOSStub_27a6 {
  strings:
    $key_27a6 = { 73 ce [2] 07 d6 [2] 40 d4 [2] 07 c5 [2] 49 c9 [2] 45 c3 [2] 52 c8 [2] 49 86 [2] 74 }

  condition:
    any of them
}