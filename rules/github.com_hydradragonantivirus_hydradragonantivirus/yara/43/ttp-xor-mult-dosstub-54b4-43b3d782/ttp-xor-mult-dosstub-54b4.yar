rule TTP_XOR_MULT_DOSStub_54b4 {
  strings:
    $key_54b4 = { 00 dc [2] 74 c4 [2] 33 c6 [2] 74 d7 [2] 3a db [2] 36 d1 [2] 21 da [2] 3a 94 [2] 07 }

  condition:
    any of them
}