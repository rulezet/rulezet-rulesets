rule TTP_XOR_MULT_DOSStub_d25f {
  strings:
    $key_d25f = { 86 37 [2] f2 2f [2] b5 2d [2] f2 3c [2] bc 30 [2] b0 3a [2] a7 31 [2] bc 7f [2] 81 }

  condition:
    any of them
}