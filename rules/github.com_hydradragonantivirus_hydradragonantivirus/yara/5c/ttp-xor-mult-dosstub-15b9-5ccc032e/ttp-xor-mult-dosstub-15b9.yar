rule TTP_XOR_MULT_DOSStub_15b9 {
  strings:
    $key_15b9 = { 41 d1 [2] 35 c9 [2] 72 cb [2] 35 da [2] 7b d6 [2] 77 dc [2] 60 d7 [2] 7b 99 [2] 46 }

  condition:
    any of them
}