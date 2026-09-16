rule TTP_XOR_MULT_DOSStub_87c7 {
  strings:
    $key_87c7 = { d3 af [2] a7 b7 [2] e0 b5 [2] a7 a4 [2] e9 a8 [2] e5 a2 [2] f2 a9 [2] e9 e7 [2] d4 }

  condition:
    any of them
}