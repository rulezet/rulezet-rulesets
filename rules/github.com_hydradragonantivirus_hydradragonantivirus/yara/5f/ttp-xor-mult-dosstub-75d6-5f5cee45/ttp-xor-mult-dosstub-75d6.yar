rule TTP_XOR_MULT_DOSStub_75d6 {
  strings:
    $key_75d6 = { 21 be [2] 55 a6 [2] 12 a4 [2] 55 b5 [2] 1b b9 [2] 17 b3 [2] 00 b8 [2] 1b f6 [2] 26 }

  condition:
    any of them
}