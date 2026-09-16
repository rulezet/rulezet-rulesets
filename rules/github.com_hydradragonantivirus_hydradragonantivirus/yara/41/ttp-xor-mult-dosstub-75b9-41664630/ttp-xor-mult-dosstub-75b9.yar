rule TTP_XOR_MULT_DOSStub_75b9 {
  strings:
    $key_75b9 = { 21 d1 [2] 55 c9 [2] 12 cb [2] 55 da [2] 1b d6 [2] 17 dc [2] 00 d7 [2] 1b 99 [2] 26 }

  condition:
    any of them
}