rule TTP_XOR_MULT_DOSStub_c3d7 {
  strings:
    $key_c3d7 = { 97 bf [2] e3 a7 [2] a4 a5 [2] e3 b4 [2] ad b8 [2] a1 b2 [2] b6 b9 [2] ad f7 [2] 90 }

  condition:
    any of them
}