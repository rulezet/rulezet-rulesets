rule TTP_XOR_MULT_DOSStub_13b9 {
  strings:
    $key_13b9 = { 47 d1 [2] 33 c9 [2] 74 cb [2] 33 da [2] 7d d6 [2] 71 dc [2] 66 d7 [2] 7d 99 [2] 40 }

  condition:
    any of them
}