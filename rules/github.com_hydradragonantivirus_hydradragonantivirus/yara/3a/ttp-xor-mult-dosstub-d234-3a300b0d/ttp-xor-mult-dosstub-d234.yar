rule TTP_XOR_MULT_DOSStub_d234 {
  strings:
    $key_d234 = { 86 5c [2] f2 44 [2] b5 46 [2] f2 57 [2] bc 5b [2] b0 51 [2] a7 5a [2] bc 14 [2] 81 }

  condition:
    any of them
}