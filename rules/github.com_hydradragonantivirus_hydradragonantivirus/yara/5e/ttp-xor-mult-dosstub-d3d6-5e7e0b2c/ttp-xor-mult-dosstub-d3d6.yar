rule TTP_XOR_MULT_DOSStub_d3d6 {
  strings:
    $key_d3d6 = { 87 be [2] f3 a6 [2] b4 a4 [2] f3 b5 [2] bd b9 [2] b1 b3 [2] a6 b8 [2] bd f6 [2] 80 }

  condition:
    any of them
}