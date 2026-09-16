rule TTP_XOR_MULT_DOSStub_17b4 {
  strings:
    $key_17b4 = { 43 dc [2] 37 c4 [2] 70 c6 [2] 37 d7 [2] 79 db [2] 75 d1 [2] 62 da [2] 79 94 [2] 44 }

  condition:
    any of them
}