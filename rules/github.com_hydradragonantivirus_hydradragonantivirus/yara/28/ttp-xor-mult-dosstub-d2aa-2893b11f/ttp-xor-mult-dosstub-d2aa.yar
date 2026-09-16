rule TTP_XOR_MULT_DOSStub_d2aa {
  strings:
    $key_d2aa = { 86 c2 [2] f2 da [2] b5 d8 [2] f2 c9 [2] bc c5 [2] b0 cf [2] a7 c4 [2] bc 8a [2] 81 }

  condition:
    any of them
}