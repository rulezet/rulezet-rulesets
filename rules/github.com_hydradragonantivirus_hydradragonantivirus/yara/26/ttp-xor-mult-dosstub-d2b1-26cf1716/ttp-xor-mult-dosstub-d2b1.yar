rule TTP_XOR_MULT_DOSStub_d2b1 {
  strings:
    $key_d2b1 = { 86 d9 [2] f2 c1 [2] b5 c3 [2] f2 d2 [2] bc de [2] b0 d4 [2] a7 df [2] bc 91 [2] 81 }

  condition:
    any of them
}