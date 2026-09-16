rule TTP_XOR_MULT_DOSStub_32b4 {
  strings:
    $key_32b4 = { 66 dc [2] 12 c4 [2] 55 c6 [2] 12 d7 [2] 5c db [2] 50 d1 [2] 47 da [2] 5c 94 [2] 61 }

  condition:
    any of them
}