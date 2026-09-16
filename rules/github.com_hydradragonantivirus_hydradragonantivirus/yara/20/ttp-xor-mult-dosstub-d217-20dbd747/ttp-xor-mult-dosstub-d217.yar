rule TTP_XOR_MULT_DOSStub_d217 {
  strings:
    $key_d217 = { 86 7f [2] f2 67 [2] b5 65 [2] f2 74 [2] bc 78 [2] b0 72 [2] a7 79 [2] bc 37 [2] 81 }

  condition:
    any of them
}