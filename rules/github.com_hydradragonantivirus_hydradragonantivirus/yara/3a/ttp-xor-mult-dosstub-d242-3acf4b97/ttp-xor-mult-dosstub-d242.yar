rule TTP_XOR_MULT_DOSStub_d242 {
  strings:
    $key_d242 = { 86 2a [2] f2 32 [2] b5 30 [2] f2 21 [2] bc 2d [2] b0 27 [2] a7 2c [2] bc 62 [2] 81 }

  condition:
    any of them
}