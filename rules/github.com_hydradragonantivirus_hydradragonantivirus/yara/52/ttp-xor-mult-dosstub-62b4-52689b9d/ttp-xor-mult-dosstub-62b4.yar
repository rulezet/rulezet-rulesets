rule TTP_XOR_MULT_DOSStub_62b4 {
  strings:
    $key_62b4 = { 36 dc [2] 42 c4 [2] 05 c6 [2] 42 d7 [2] 0c db [2] 00 d1 [2] 17 da [2] 0c 94 [2] 31 }

  condition:
    any of them
}