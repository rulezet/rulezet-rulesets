rule TTP_XOR_MULT_DOSStub_07b9 {
  strings:
    $key_07b9 = { 53 d1 [2] 27 c9 [2] 60 cb [2] 27 da [2] 69 d6 [2] 65 dc [2] 72 d7 [2] 69 99 [2] 54 }

  condition:
    any of them
}