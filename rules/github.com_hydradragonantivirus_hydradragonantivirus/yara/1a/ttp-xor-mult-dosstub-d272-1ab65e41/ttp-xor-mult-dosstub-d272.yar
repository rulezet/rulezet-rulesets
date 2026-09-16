rule TTP_XOR_MULT_DOSStub_d272 {
  strings:
    $key_d272 = { 86 1a [2] f2 02 [2] b5 00 [2] f2 11 [2] bc 1d [2] b0 17 [2] a7 1c [2] bc 52 [2] 81 }

  condition:
    any of them
}