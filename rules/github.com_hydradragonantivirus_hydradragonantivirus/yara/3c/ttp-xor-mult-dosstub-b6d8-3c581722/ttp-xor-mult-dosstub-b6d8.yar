rule TTP_XOR_MULT_DOSStub_b6d8 {
  strings:
    $key_b6d8 = { e2 b0 [2] 96 a8 [2] d1 aa [2] 96 bb [2] d8 b7 [2] d4 bd [2] c3 b6 [2] d8 f8 [2] e5 }

  condition:
    any of them
}