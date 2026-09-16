rule TTP_XOR_MULT_DOSStub_d2a4 {
  strings:
    $key_d2a4 = { 86 cc [2] f2 d4 [2] b5 d6 [2] f2 c7 [2] bc cb [2] b0 c1 [2] a7 ca [2] bc 84 [2] 81 }

  condition:
    any of them
}