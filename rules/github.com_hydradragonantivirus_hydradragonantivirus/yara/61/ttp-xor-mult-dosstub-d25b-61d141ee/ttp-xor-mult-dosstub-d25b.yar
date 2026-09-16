rule TTP_XOR_MULT_DOSStub_d25b {
  strings:
    $key_d25b = { 86 33 [2] f2 2b [2] b5 29 [2] f2 38 [2] bc 34 [2] b0 3e [2] a7 35 [2] bc 7b [2] 81 }

  condition:
    any of them
}