rule TTP_XOR_MULT_DOSStub_d2f2 {
  strings:
    $key_d2f2 = { 86 9a [2] f2 82 [2] b5 80 [2] f2 91 [2] bc 9d [2] b0 97 [2] a7 9c [2] bc d2 [2] 81 }

  condition:
    any of them
}