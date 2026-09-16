rule TTP_XOR_MULT_DOSStub_d24c {
  strings:
    $key_d24c = { 86 24 [2] f2 3c [2] b5 3e [2] f2 2f [2] bc 23 [2] b0 29 [2] a7 22 [2] bc 6c [2] 81 }

  condition:
    any of them
}