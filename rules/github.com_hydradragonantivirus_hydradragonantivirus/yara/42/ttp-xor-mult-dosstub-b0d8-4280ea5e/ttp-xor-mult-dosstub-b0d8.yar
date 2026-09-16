rule TTP_XOR_MULT_DOSStub_b0d8 {
  strings:
    $key_b0d8 = { e4 b0 [2] 90 a8 [2] d7 aa [2] 90 bb [2] de b7 [2] d2 bd [2] c5 b6 [2] de f8 [2] e3 }

  condition:
    any of them
}