rule TTP_XOR_MULT_DOSStub_d2ac {
  strings:
    $key_d2ac = { 86 c4 [2] f2 dc [2] b5 de [2] f2 cf [2] bc c3 [2] b0 c9 [2] a7 c2 [2] bc 8c [2] 81 }

  condition:
    any of them
}