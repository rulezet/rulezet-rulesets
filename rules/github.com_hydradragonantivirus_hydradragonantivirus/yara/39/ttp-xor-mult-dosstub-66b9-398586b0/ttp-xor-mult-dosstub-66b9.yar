rule TTP_XOR_MULT_DOSStub_66b9 {
  strings:
    $key_66b9 = { 32 d1 [2] 46 c9 [2] 01 cb [2] 46 da [2] 08 d6 [2] 04 dc [2] 13 d7 [2] 08 99 [2] 35 }

  condition:
    any of them
}