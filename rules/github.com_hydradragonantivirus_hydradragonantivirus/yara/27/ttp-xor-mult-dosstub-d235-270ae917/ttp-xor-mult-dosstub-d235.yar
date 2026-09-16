rule TTP_XOR_MULT_DOSStub_d235 {
  strings:
    $key_d235 = { 86 5d [2] f2 45 [2] b5 47 [2] f2 56 [2] bc 5a [2] b0 50 [2] a7 5b [2] bc 15 [2] 81 }

  condition:
    any of them
}