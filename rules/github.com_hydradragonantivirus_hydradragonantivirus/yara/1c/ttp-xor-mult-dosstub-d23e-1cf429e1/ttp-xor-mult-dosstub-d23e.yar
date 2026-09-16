rule TTP_XOR_MULT_DOSStub_d23e {
  strings:
    $key_d23e = { 86 56 [2] f2 4e [2] b5 4c [2] f2 5d [2] bc 51 [2] b0 5b [2] a7 50 [2] bc 1e [2] 81 }

  condition:
    any of them
}