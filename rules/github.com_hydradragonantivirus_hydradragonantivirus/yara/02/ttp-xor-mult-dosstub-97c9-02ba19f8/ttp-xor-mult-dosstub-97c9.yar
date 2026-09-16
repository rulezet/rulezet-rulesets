rule TTP_XOR_MULT_DOSStub_97c9 {
  strings:
    $key_97c9 = { c3 a1 [2] b7 b9 [2] f0 bb [2] b7 aa [2] f9 a6 [2] f5 ac [2] e2 a7 [2] f9 e9 [2] c4 }

  condition:
    any of them
}