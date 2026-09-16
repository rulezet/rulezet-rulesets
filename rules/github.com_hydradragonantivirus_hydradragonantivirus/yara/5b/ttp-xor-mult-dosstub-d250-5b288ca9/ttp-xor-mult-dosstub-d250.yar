rule TTP_XOR_MULT_DOSStub_d250 {
  strings:
    $key_d250 = { 86 38 [2] f2 20 [2] b5 22 [2] f2 33 [2] bc 3f [2] b0 35 [2] a7 3e [2] bc 70 [2] 81 }

  condition:
    any of them
}