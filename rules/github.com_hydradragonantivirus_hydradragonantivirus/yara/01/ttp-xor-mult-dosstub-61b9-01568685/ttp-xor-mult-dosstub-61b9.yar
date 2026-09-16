rule TTP_XOR_MULT_DOSStub_61b9 {
  strings:
    $key_61b9 = { 35 d1 [2] 41 c9 [2] 06 cb [2] 41 da [2] 0f d6 [2] 03 dc [2] 14 d7 [2] 0f 99 [2] 32 }

  condition:
    any of them
}