rule TTP_XOR_MULT_DOSStub_d215 {
  strings:
    $key_d215 = { 86 7d [2] f2 65 [2] b5 67 [2] f2 76 [2] bc 7a [2] b0 70 [2] a7 7b [2] bc 35 [2] 81 }

  condition:
    any of them
}