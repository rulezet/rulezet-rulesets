rule TTP_XOR_MULT_DOSStub_d263 {
  strings:
    $key_d263 = { 86 0b [2] f2 13 [2] b5 11 [2] f2 00 [2] bc 0c [2] b0 06 [2] a7 0d [2] bc 43 [2] 81 }

  condition:
    any of them
}