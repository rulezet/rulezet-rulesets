rule TTP_XOR_MULT_DOSStub_d25c {
  strings:
    $key_d25c = { 86 34 [2] f2 2c [2] b5 2e [2] f2 3f [2] bc 33 [2] b0 39 [2] a7 32 [2] bc 7c [2] 81 }

  condition:
    any of them
}