rule TTP_XOR_MULT_DOSStub_d232 {
  strings:
    $key_d232 = { 86 5a [2] f2 42 [2] b5 40 [2] f2 51 [2] bc 5d [2] b0 57 [2] a7 5c [2] bc 12 [2] 81 }

  condition:
    any of them
}