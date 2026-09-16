rule TTP_XOR_MULT_DOSStub_d224 {
  strings:
    $key_d224 = { 86 4c [2] f2 54 [2] b5 56 [2] f2 47 [2] bc 4b [2] b0 41 [2] a7 4a [2] bc 04 [2] 81 }

  condition:
    any of them
}