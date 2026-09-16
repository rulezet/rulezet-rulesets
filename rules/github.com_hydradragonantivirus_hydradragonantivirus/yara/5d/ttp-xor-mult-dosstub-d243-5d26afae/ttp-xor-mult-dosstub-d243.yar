rule TTP_XOR_MULT_DOSStub_d243 {
  strings:
    $key_d243 = { 86 2b [2] f2 33 [2] b5 31 [2] f2 20 [2] bc 2c [2] b0 26 [2] a7 2d [2] bc 63 [2] 81 }

  condition:
    any of them
}