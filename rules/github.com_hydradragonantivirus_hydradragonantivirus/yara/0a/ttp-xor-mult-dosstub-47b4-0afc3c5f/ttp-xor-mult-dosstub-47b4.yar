rule TTP_XOR_MULT_DOSStub_47b4 {
  strings:
    $key_47b4 = { 13 dc [2] 67 c4 [2] 20 c6 [2] 67 d7 [2] 29 db [2] 25 d1 [2] 32 da [2] 29 94 [2] 14 }

  condition:
    any of them
}