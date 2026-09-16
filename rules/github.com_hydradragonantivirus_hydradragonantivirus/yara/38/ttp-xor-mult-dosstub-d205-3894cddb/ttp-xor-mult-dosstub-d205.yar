rule TTP_XOR_MULT_DOSStub_d205 {
  strings:
    $key_d205 = { 86 6d [2] f2 75 [2] b5 77 [2] f2 66 [2] bc 6a [2] b0 60 [2] a7 6b [2] bc 25 [2] 81 }

  condition:
    any of them
}