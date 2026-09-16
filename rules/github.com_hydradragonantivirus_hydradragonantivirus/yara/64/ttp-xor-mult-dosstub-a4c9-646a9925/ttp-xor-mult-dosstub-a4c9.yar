rule TTP_XOR_MULT_DOSStub_a4c9 {
  strings:
    $key_a4c9 = { f0 a1 [2] 84 b9 [2] c3 bb [2] 84 aa [2] ca a6 [2] c6 ac [2] d1 a7 [2] ca e9 [2] f7 }

  condition:
    any of them
}