rule TTP_XOR_MULT_DOSStub_d213 {
  strings:
    $key_d213 = { 86 7b [2] f2 63 [2] b5 61 [2] f2 70 [2] bc 7c [2] b0 76 [2] a7 7d [2] bc 33 [2] 81 }

  condition:
    any of them
}