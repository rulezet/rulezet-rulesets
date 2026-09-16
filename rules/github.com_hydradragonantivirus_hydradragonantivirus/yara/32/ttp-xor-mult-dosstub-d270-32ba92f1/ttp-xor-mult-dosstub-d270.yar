rule TTP_XOR_MULT_DOSStub_d270 {
  strings:
    $key_d270 = { 86 18 [2] f2 00 [2] b5 02 [2] f2 13 [2] bc 1f [2] b0 15 [2] a7 1e [2] bc 50 [2] 81 }

  condition:
    any of them
}