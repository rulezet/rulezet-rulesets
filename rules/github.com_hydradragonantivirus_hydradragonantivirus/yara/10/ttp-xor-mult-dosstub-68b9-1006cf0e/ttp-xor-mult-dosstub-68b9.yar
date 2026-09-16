rule TTP_XOR_MULT_DOSStub_68b9 {
  strings:
    $key_68b9 = { 3c d1 [2] 48 c9 [2] 0f cb [2] 48 da [2] 06 d6 [2] 0a dc [2] 1d d7 [2] 06 99 [2] 3b }

  condition:
    any of them
}