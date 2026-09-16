rule TTP_XOR_MULT_DOSStub_55b9 {
  strings:
    $key_55b9 = { 01 d1 [2] 75 c9 [2] 32 cb [2] 75 da [2] 3b d6 [2] 37 dc [2] 20 d7 [2] 3b 99 [2] 06 }

  condition:
    any of them
}