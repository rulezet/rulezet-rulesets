rule TTP_XOR_MULT_DOSStub_56b4 {
  strings:
    $key_56b4 = { 02 dc [2] 76 c4 [2] 31 c6 [2] 76 d7 [2] 38 db [2] 34 d1 [2] 23 da [2] 38 94 [2] 05 }

  condition:
    any of them
}