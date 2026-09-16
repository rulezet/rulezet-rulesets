rule TTP_XOR_MULT_DOSStub_d2c7 {
  strings:
    $key_d2c7 = { 86 af [2] f2 b7 [2] b5 b5 [2] f2 a4 [2] bc a8 [2] b0 a2 [2] a7 a9 [2] bc e7 [2] 81 }

  condition:
    any of them
}