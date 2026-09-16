rule TTP_XOR_MULT_DOSStub_d2d0 {
  strings:
    $key_d2d0 = { 86 b8 [2] f2 a0 [2] b5 a2 [2] f2 b3 [2] bc bf [2] b0 b5 [2] a7 be [2] bc f0 [2] 81 }

  condition:
    any of them
}