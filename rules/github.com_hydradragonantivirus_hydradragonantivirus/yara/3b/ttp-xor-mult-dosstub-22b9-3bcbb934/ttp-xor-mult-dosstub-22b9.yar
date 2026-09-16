rule TTP_XOR_MULT_DOSStub_22b9 {
  strings:
    $key_22b9 = { 76 d1 [2] 02 c9 [2] 45 cb [2] 02 da [2] 4c d6 [2] 40 dc [2] 57 d7 [2] 4c 99 [2] 71 }

  condition:
    any of them
}