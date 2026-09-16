rule TTP_XOR_MULT_DOSStub_a1c9 {
  strings:
    $key_a1c9 = { f5 a1 [2] 81 b9 [2] c6 bb [2] 81 aa [2] cf a6 [2] c3 ac [2] d4 a7 [2] cf e9 [2] f2 }

  condition:
    any of them
}