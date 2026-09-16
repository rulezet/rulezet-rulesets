rule TTP_XOR_MULT_DOSStub_d2b4 {
  strings:
    $key_d2b4 = { 86 dc [2] f2 c4 [2] b5 c6 [2] f2 d7 [2] bc db [2] b0 d1 [2] a7 da [2] bc 94 [2] 81 }

  condition:
    any of them
}