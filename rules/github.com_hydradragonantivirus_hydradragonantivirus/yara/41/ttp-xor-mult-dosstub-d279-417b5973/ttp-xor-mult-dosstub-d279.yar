rule TTP_XOR_MULT_DOSStub_d279 {
  strings:
    $key_d279 = { 86 11 [2] f2 09 [2] b5 0b [2] f2 1a [2] bc 16 [2] b0 1c [2] a7 17 [2] bc 59 [2] 81 }

  condition:
    any of them
}