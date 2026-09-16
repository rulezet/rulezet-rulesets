rule TTP_XOR_MULT_DOSStub_36b9 {
  strings:
    $key_36b9 = { 62 d1 [2] 16 c9 [2] 51 cb [2] 16 da [2] 58 d6 [2] 54 dc [2] 43 d7 [2] 58 99 [2] 65 }

  condition:
    any of them
}