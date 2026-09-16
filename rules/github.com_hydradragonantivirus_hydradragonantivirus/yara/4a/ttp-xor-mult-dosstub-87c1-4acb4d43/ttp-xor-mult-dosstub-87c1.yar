rule TTP_XOR_MULT_DOSStub_87c1 {
  strings:
    $key_87c1 = { d3 a9 [2] a7 b1 [2] e0 b3 [2] a7 a2 [2] e9 ae [2] e5 a4 [2] f2 af [2] e9 e1 [2] d4 }

  condition:
    any of them
}