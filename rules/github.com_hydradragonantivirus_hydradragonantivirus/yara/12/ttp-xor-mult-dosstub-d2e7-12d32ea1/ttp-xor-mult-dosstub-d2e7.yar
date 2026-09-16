rule TTP_XOR_MULT_DOSStub_d2e7 {
  strings:
    $key_d2e7 = { 86 8f [2] f2 97 [2] b5 95 [2] f2 84 [2] bc 88 [2] b0 82 [2] a7 89 [2] bc c7 [2] 81 }

  condition:
    any of them
}