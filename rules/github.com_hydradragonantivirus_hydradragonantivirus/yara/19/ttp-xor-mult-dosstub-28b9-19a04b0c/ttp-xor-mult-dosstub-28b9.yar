rule TTP_XOR_MULT_DOSStub_28b9 {
  strings:
    $key_28b9 = { 7c d1 [2] 08 c9 [2] 4f cb [2] 08 da [2] 46 d6 [2] 4a dc [2] 5d d7 [2] 46 99 [2] 7b }

  condition:
    any of them
}