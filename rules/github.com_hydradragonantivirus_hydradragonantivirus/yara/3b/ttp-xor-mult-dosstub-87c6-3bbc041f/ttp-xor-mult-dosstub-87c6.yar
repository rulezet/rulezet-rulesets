rule TTP_XOR_MULT_DOSStub_87c6 {
  strings:
    $key_87c6 = { d3 ae [2] a7 b6 [2] e0 b4 [2] a7 a5 [2] e9 a9 [2] e5 a3 [2] f2 a8 [2] e9 e6 [2] d4 }

  condition:
    any of them
}