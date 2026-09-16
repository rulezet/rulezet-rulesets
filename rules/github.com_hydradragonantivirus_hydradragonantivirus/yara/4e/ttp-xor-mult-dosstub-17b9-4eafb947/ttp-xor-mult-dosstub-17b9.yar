rule TTP_XOR_MULT_DOSStub_17b9 {
  strings:
    $key_17b9 = { 43 d1 [2] 37 c9 [2] 70 cb [2] 37 da [2] 79 d6 [2] 75 dc [2] 62 d7 [2] 79 99 [2] 44 }

  condition:
    any of them
}