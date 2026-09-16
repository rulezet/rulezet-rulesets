rule TTP_XOR_MULT_DOSStub_85c9 {
  strings:
    $key_85c9 = { d1 a1 [2] a5 b9 [2] e2 bb [2] a5 aa [2] eb a6 [2] e7 ac [2] f0 a7 [2] eb e9 [2] d6 }

  condition:
    any of them
}