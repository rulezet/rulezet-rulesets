rule TTP_XOR_MULT_DOSStub_26b9 {
  strings:
    $key_26b9 = { 72 d1 [2] 06 c9 [2] 41 cb [2] 06 da [2] 48 d6 [2] 44 dc [2] 53 d7 [2] 48 99 [2] 75 }

  condition:
    any of them
}