rule TTP_XOR_MULT_DOSStub_d251 {
  strings:
    $key_d251 = { 86 39 [2] f2 21 [2] b5 23 [2] f2 32 [2] bc 3e [2] b0 34 [2] a7 3f [2] bc 71 [2] 81 }

  condition:
    any of them
}