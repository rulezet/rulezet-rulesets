rule TTP_XOR_MULT_DOSStub_d260 {
  strings:
    $key_d260 = { 86 08 [2] f2 10 [2] b5 12 [2] f2 03 [2] bc 0f [2] b0 05 [2] a7 0e [2] bc 40 [2] 81 }

  condition:
    any of them
}