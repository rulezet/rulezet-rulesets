rule TTP_XOR_MULT_DOSStub_42b9 {
  strings:
    $key_42b9 = { 16 d1 [2] 62 c9 [2] 25 cb [2] 62 da [2] 2c d6 [2] 20 dc [2] 37 d7 [2] 2c 99 [2] 11 }

  condition:
    any of them
}