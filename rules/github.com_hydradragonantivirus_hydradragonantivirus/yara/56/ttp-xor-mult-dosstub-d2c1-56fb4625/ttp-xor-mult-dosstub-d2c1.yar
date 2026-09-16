rule TTP_XOR_MULT_DOSStub_d2c1 {
  strings:
    $key_d2c1 = { 86 a9 [2] f2 b1 [2] b5 b3 [2] f2 a2 [2] bc ae [2] b0 a4 [2] a7 af [2] bc e1 [2] 81 }

  condition:
    any of them
}