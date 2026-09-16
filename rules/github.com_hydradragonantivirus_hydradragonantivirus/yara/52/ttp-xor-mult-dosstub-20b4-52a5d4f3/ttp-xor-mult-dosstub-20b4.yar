rule TTP_XOR_MULT_DOSStub_20b4 {
  strings:
    $key_20b4 = { 74 dc [2] 00 c4 [2] 47 c6 [2] 00 d7 [2] 4e db [2] 42 d1 [2] 55 da [2] 4e 94 [2] 73 }

  condition:
    any of them
}