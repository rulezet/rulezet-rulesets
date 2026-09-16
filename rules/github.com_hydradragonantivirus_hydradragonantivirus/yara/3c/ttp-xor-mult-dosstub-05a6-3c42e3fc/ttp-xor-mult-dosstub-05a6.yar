rule TTP_XOR_MULT_DOSStub_05a6 {
  strings:
    $key_05a6 = { 51 ce [2] 25 d6 [2] 62 d4 [2] 25 c5 [2] 6b c9 [2] 67 c3 [2] 70 c8 [2] 6b 86 [2] 56 }

  condition:
    any of them
}