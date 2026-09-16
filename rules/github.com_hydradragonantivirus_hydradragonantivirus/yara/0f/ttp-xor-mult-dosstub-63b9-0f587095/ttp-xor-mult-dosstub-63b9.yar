rule TTP_XOR_MULT_DOSStub_63b9 {
  strings:
    $key_63b9 = { 37 d1 [2] 43 c9 [2] 04 cb [2] 43 da [2] 0d d6 [2] 01 dc [2] 16 d7 [2] 0d 99 [2] 30 }

  condition:
    any of them
}