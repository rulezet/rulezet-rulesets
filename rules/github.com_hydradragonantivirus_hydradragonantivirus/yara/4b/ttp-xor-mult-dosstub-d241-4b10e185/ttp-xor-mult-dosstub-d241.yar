rule TTP_XOR_MULT_DOSStub_d241 {
  strings:
    $key_d241 = { 86 29 [2] f2 31 [2] b5 33 [2] f2 22 [2] bc 2e [2] b0 24 [2] a7 2f [2] bc 61 [2] 81 }

  condition:
    any of them
}