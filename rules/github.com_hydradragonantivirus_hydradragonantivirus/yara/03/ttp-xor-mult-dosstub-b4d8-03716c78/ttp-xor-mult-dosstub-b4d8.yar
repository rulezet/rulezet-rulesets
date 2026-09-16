rule TTP_XOR_MULT_DOSStub_b4d8 {
  strings:
    $key_b4d8 = { e0 b0 [2] 94 a8 [2] d3 aa [2] 94 bb [2] da b7 [2] d6 bd [2] c1 b6 [2] da f8 [2] e7 }

  condition:
    any of them
}