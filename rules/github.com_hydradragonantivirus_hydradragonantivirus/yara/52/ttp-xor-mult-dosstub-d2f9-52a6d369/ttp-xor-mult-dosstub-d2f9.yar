rule TTP_XOR_MULT_DOSStub_d2f9 {
  strings:
    $key_d2f9 = { 86 91 [2] f2 89 [2] b5 8b [2] f2 9a [2] bc 96 [2] b0 9c [2] a7 97 [2] bc d9 [2] 81 }

  condition:
    any of them
}