rule TTP_XOR_MULT_DOSStub_74b4 {
  strings:
    $key_74b4 = { 20 dc [2] 54 c4 [2] 13 c6 [2] 54 d7 [2] 1a db [2] 16 d1 [2] 01 da [2] 1a 94 [2] 27 }

  condition:
    any of them
}