rule TTP_XOR_MULT_DOSStub_b1d8 {
  strings:
    $key_b1d8 = { e5 b0 [2] 91 a8 [2] d6 aa [2] 91 bb [2] df b7 [2] d3 bd [2] c4 b6 [2] df f8 [2] e2 }

  condition:
    any of them
}