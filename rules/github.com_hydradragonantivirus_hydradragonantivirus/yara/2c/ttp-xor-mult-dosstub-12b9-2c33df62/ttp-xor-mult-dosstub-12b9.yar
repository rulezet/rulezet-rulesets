rule TTP_XOR_MULT_DOSStub_12b9 {
  strings:
    $key_12b9 = { 46 d1 [2] 32 c9 [2] 75 cb [2] 32 da [2] 7c d6 [2] 70 dc [2] 67 d7 [2] 7c 99 [2] 41 }

  condition:
    any of them
}