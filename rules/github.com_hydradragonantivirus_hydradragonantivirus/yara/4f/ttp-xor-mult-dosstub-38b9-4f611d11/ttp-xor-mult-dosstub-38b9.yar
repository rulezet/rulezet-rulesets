rule TTP_XOR_MULT_DOSStub_38b9 {
  strings:
    $key_38b9 = { 6c d1 [2] 18 c9 [2] 5f cb [2] 18 da [2] 56 d6 [2] 5a dc [2] 4d d7 [2] 56 99 [2] 6b }

  condition:
    any of them
}