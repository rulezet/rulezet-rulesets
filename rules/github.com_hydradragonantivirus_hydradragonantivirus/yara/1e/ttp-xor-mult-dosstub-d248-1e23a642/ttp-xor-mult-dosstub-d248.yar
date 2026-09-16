rule TTP_XOR_MULT_DOSStub_d248 {
  strings:
    $key_d248 = { 86 20 [2] f2 38 [2] b5 3a [2] f2 2b [2] bc 27 [2] b0 2d [2] a7 26 [2] bc 68 [2] 81 }

  condition:
    any of them
}