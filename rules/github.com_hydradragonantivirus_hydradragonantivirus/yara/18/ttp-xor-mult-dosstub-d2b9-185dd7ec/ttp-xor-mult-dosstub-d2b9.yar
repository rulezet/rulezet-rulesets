rule TTP_XOR_MULT_DOSStub_d2b9 {
  strings:
    $key_d2b9 = { 86 d1 [2] f2 c9 [2] b5 cb [2] f2 da [2] bc d6 [2] b0 dc [2] a7 d7 [2] bc 99 [2] 81 }

  condition:
    any of them
}