rule TTP_XOR_MULT_DOSStub_d2a6 {
  strings:
    $key_d2a6 = { 86 ce [2] f2 d6 [2] b5 d4 [2] f2 c5 [2] bc c9 [2] b0 c3 [2] a7 c8 [2] bc 86 [2] 81 }

  condition:
    any of them
}