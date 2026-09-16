rule TTP_XOR_MULT_DOSStub_62b9 {
  strings:
    $key_62b9 = { 36 d1 [2] 42 c9 [2] 05 cb [2] 42 da [2] 0c d6 [2] 00 dc [2] 17 d7 [2] 0c 99 [2] 31 }

  condition:
    any of them
}