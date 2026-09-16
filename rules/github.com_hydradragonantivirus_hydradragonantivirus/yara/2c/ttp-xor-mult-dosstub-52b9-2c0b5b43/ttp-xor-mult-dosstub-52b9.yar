rule TTP_XOR_MULT_DOSStub_52b9 {
  strings:
    $key_52b9 = { 06 d1 [2] 72 c9 [2] 35 cb [2] 72 da [2] 3c d6 [2] 30 dc [2] 27 d7 [2] 3c 99 [2] 01 }

  condition:
    any of them
}