rule TTP_XOR_MULT_DOSStub_64b9 {
  strings:
    $key_64b9 = { 30 d1 [2] 44 c9 [2] 03 cb [2] 44 da [2] 0a d6 [2] 06 dc [2] 11 d7 [2] 0a 99 [2] 37 }

  condition:
    any of them
}