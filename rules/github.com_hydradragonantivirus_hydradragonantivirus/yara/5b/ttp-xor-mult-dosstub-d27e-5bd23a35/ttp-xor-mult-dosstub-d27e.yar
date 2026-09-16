rule TTP_XOR_MULT_DOSStub_d27e {
  strings:
    $key_d27e = { 86 16 [2] f2 0e [2] b5 0c [2] f2 1d [2] bc 11 [2] b0 1b [2] a7 10 [2] bc 5e [2] 81 }

  condition:
    any of them
}