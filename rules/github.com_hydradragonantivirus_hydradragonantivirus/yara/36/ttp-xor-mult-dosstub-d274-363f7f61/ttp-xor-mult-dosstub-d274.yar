rule TTP_XOR_MULT_DOSStub_d274 {
  strings:
    $key_d274 = { 86 1c [2] f2 04 [2] b5 06 [2] f2 17 [2] bc 1b [2] b0 11 [2] a7 1a [2] bc 54 [2] 81 }

  condition:
    any of them
}