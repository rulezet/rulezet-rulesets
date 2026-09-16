rule TTP_XOR_MULT_DOSStub_d3d9 {
  strings:
    $key_d3d9 = { 87 b1 [2] f3 a9 [2] b4 ab [2] f3 ba [2] bd b6 [2] b1 bc [2] a6 b7 [2] bd f9 [2] 80 }

  condition:
    any of them
}