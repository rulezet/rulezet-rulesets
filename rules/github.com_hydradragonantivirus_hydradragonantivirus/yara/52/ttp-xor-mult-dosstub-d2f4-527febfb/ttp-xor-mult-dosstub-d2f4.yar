rule TTP_XOR_MULT_DOSStub_d2f4 {
  strings:
    $key_d2f4 = { 86 9c [2] f2 84 [2] b5 86 [2] f2 97 [2] bc 9b [2] b0 91 [2] a7 9a [2] bc d4 [2] 81 }

  condition:
    any of them
}