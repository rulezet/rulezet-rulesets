rule TTP_XOR_MULT_DOSStub_d211 {
  strings:
    $key_d211 = { 86 79 [2] f2 61 [2] b5 63 [2] f2 72 [2] bc 7e [2] b0 74 [2] a7 7f [2] bc 31 [2] 81 }

  condition:
    any of them
}