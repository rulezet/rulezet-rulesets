rule TTP_XOR_MULT_DOSStub_d2f6 {
  strings:
    $key_d2f6 = { 86 9e [2] f2 86 [2] b5 84 [2] f2 95 [2] bc 99 [2] b0 93 [2] a7 98 [2] bc d6 [2] 81 }

  condition:
    any of them
}