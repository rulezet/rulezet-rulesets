rule TTP_XOR_MULT_DOSStub_75b4 {
  strings:
    $key_75b4 = { 21 dc [2] 55 c4 [2] 12 c6 [2] 55 d7 [2] 1b db [2] 17 d1 [2] 00 da [2] 1b 94 [2] 26 }

  condition:
    any of them
}