rule TTP_XOR_MULT_DOSStub_d209 {
  strings:
    $key_d209 = { 86 61 [2] f2 79 [2] b5 7b [2] f2 6a [2] bc 66 [2] b0 6c [2] a7 67 [2] bc 29 [2] 81 }

  condition:
    any of them
}