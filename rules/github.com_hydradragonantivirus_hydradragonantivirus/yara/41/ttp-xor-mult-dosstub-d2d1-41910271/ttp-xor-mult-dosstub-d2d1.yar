rule TTP_XOR_MULT_DOSStub_d2d1 {
  strings:
    $key_d2d1 = { 86 b9 [2] f2 a1 [2] b5 a3 [2] f2 b2 [2] bc be [2] b0 b4 [2] a7 bf [2] bc f1 [2] 81 }

  condition:
    any of them
}