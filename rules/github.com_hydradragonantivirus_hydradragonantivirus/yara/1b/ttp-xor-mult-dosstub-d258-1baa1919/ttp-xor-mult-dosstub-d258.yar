rule TTP_XOR_MULT_DOSStub_d258 {
  strings:
    $key_d258 = { 86 30 [2] f2 28 [2] b5 2a [2] f2 3b [2] bc 37 [2] b0 3d [2] a7 36 [2] bc 78 [2] 81 }

  condition:
    any of them
}