rule TTP_XOR_MULT_DOSStub_d254 {
  strings:
    $key_d254 = { 86 3c [2] f2 24 [2] b5 26 [2] f2 37 [2] bc 3b [2] b0 31 [2] a7 3a [2] bc 74 [2] 81 }

  condition:
    any of them
}