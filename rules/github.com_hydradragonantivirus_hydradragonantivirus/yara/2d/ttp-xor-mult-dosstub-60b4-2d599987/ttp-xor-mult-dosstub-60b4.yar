rule TTP_XOR_MULT_DOSStub_60b4 {
  strings:
    $key_60b4 = { 34 dc [2] 40 c4 [2] 07 c6 [2] 40 d7 [2] 0e db [2] 02 d1 [2] 15 da [2] 0e 94 [2] 33 }

  condition:
    any of them
}