rule TTP_XOR_MULT_DOSStub_12b4 {
  strings:
    $key_12b4 = { 46 dc [2] 32 c4 [2] 75 c6 [2] 32 d7 [2] 7c db [2] 70 d1 [2] 67 da [2] 7c 94 [2] 41 }

  condition:
    any of them
}