rule TTP_XOR_MULT_DOSStub_d239 {
  strings:
    $key_d239 = { 86 51 [2] f2 49 [2] b5 4b [2] f2 5a [2] bc 56 [2] b0 5c [2] a7 57 [2] bc 19 [2] 81 }

  condition:
    any of them
}