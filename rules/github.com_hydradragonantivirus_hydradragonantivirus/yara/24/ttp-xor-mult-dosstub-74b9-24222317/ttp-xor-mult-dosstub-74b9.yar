rule TTP_XOR_MULT_DOSStub_74b9 {
  strings:
    $key_74b9 = { 20 d1 [2] 54 c9 [2] 13 cb [2] 54 da [2] 1a d6 [2] 16 dc [2] 01 d7 [2] 1a 99 [2] 27 }

  condition:
    any of them
}