rule TTP_XOR_MULT_DOSStub_d22e {
  strings:
    $key_d22e = { 86 46 [2] f2 5e [2] b5 5c [2] f2 4d [2] bc 41 [2] b0 4b [2] a7 40 [2] bc 0e [2] 81 }

  condition:
    any of them
}