rule TTP_XOR_MULT_DOSStub_87c4 {
  strings:
    $key_87c4 = { d3 ac [2] a7 b4 [2] e0 b6 [2] a7 a7 [2] e9 ab [2] e5 a1 [2] f2 aa [2] e9 e4 [2] d4 }

  condition:
    any of them
}