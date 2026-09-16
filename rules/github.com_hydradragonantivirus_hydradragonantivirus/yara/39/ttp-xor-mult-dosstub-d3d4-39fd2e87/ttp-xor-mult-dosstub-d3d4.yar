rule TTP_XOR_MULT_DOSStub_d3d4 {
  strings:
    $key_d3d4 = { 87 bc [2] f3 a4 [2] b4 a6 [2] f3 b7 [2] bd bb [2] b1 b1 [2] a6 ba [2] bd f4 [2] 80 }

  condition:
    any of them
}