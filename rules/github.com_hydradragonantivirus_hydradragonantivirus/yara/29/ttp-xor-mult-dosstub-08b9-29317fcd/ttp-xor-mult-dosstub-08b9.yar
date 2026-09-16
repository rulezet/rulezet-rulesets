rule TTP_XOR_MULT_DOSStub_08b9 {
  strings:
    $key_08b9 = { 5c d1 [2] 28 c9 [2] 6f cb [2] 28 da [2] 66 d6 [2] 6a dc [2] 7d d7 [2] 66 99 [2] 5b }

  condition:
    any of them
}