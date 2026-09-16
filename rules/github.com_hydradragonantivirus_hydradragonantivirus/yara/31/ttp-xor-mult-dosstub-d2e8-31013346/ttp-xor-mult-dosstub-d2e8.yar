rule TTP_XOR_MULT_DOSStub_d2e8 {
  strings:
    $key_d2e8 = { 86 80 [2] f2 98 [2] b5 9a [2] f2 8b [2] bc 87 [2] b0 8d [2] a7 86 [2] bc c8 [2] 81 }

  condition:
    any of them
}