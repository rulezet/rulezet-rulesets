rule TTP_XOR_MULT_DOSStub_33b9 {
  strings:
    $key_33b9 = { 67 d1 [2] 13 c9 [2] 54 cb [2] 13 da [2] 5d d6 [2] 51 dc [2] 46 d7 [2] 5d 99 [2] 60 }

  condition:
    any of them
}