rule TTP_XOR_MULT_DOSStub_85c4 {
  strings:
    $key_85c4 = { d1 ac [2] a5 b4 [2] e2 b6 [2] a5 a7 [2] eb ab [2] e7 a1 [2] f0 aa [2] eb e4 [2] d6 }

  condition:
    any of them
}