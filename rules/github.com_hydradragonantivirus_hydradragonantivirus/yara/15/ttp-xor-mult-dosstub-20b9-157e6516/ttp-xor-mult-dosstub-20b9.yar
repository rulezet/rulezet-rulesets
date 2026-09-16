rule TTP_XOR_MULT_DOSStub_20b9 {
  strings:
    $key_20b9 = { 74 d1 [2] 00 c9 [2] 47 cb [2] 00 da [2] 4e d6 [2] 42 dc [2] 55 d7 [2] 4e 99 [2] 73 }

  condition:
    any of them
}