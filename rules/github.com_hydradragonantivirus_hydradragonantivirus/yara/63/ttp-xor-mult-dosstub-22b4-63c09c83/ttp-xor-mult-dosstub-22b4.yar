rule TTP_XOR_MULT_DOSStub_22b4 {
  strings:
    $key_22b4 = { 76 dc [2] 02 c4 [2] 45 c6 [2] 02 d7 [2] 4c db [2] 40 d1 [2] 57 da [2] 4c 94 [2] 71 }

  condition:
    any of them
}