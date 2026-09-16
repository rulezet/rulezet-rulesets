rule TTP_XOR_MULT_DOSStub_d3c1 {
  strings:
    $key_d3c1 = { 87 a9 [2] f3 b1 [2] b4 b3 [2] f3 a2 [2] bd ae [2] b1 a4 [2] a6 af [2] bd e1 [2] 80 }

  condition:
    any of them
}