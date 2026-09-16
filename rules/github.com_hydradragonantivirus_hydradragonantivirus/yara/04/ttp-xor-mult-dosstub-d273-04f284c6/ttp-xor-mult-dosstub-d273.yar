rule TTP_XOR_MULT_DOSStub_d273 {
  strings:
    $key_d273 = { 86 1b [2] f2 03 [2] b5 01 [2] f2 10 [2] bc 1c [2] b0 16 [2] a7 1d [2] bc 53 [2] 81 }

  condition:
    any of them
}