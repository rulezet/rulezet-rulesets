rule TTP_XOR_MULT_DOSStub_87c2 {
  strings:
    $key_87c2 = { d3 aa [2] a7 b2 [2] e0 b0 [2] a7 a1 [2] e9 ad [2] e5 a7 [2] f2 ac [2] e9 e2 [2] d4 }

  condition:
    any of them
}