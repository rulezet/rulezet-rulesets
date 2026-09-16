rule TTP_XOR_MULT_DOSStub_77b4 {
  strings:
    $key_77b4 = { 23 dc [2] 57 c4 [2] 10 c6 [2] 57 d7 [2] 19 db [2] 15 d1 [2] 02 da [2] 19 94 [2] 24 }

  condition:
    any of them
}