rule TTP_XOR_MULT_DOSStub_24b9 {
  strings:
    $key_24b9 = { 70 d1 [2] 04 c9 [2] 43 cb [2] 04 da [2] 4a d6 [2] 46 dc [2] 51 d7 [2] 4a 99 [2] 77 }

  condition:
    any of them
}