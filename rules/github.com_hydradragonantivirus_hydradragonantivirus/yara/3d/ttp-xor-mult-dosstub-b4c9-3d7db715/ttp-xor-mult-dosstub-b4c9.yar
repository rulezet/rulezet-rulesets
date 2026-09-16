rule TTP_XOR_MULT_DOSStub_b4c9 {
  strings:
    $key_b4c9 = { e0 a1 [2] 94 b9 [2] d3 bb [2] 94 aa [2] da a6 [2] d6 ac [2] c1 a7 [2] da e9 [2] e7 }

  condition:
    any of them
}