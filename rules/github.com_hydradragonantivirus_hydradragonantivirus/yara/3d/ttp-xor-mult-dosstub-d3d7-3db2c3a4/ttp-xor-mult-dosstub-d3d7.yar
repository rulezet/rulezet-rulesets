rule TTP_XOR_MULT_DOSStub_d3d7 {
  strings:
    $key_d3d7 = { 87 bf [2] f3 a7 [2] b4 a5 [2] f3 b4 [2] bd b8 [2] b1 b2 [2] a6 b9 [2] bd f7 [2] 80 }

  condition:
    any of them
}