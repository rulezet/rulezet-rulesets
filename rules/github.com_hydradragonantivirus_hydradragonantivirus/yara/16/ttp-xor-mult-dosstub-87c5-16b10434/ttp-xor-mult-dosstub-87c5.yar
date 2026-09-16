rule TTP_XOR_MULT_DOSStub_87c5 {
  strings:
    $key_87c5 = { d3 ad [2] a7 b5 [2] e0 b7 [2] a7 a6 [2] e9 aa [2] e5 a0 [2] f2 ab [2] e9 e5 [2] d4 }

  condition:
    any of them
}