rule TTP_XOR_MULT_DOSStub_d236 {
  strings:
    $key_d236 = { 86 5e [2] f2 46 [2] b5 44 [2] f2 55 [2] bc 59 [2] b0 53 [2] a7 58 [2] bc 16 [2] 81 }

  condition:
    any of them
}