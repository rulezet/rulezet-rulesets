rule TTP_XOR_MULT_DOSStub_64b4 {
  strings:
    $key_64b4 = { 30 dc [2] 44 c4 [2] 03 c6 [2] 44 d7 [2] 0a db [2] 06 d1 [2] 11 da [2] 0a 94 [2] 37 }

  condition:
    any of them
}