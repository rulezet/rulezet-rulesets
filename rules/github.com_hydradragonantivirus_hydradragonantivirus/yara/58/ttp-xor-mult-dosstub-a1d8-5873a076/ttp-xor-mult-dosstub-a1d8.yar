rule TTP_XOR_MULT_DOSStub_a1d8 {
  strings:
    $key_a1d8 = { f5 b0 [2] 81 a8 [2] c6 aa [2] 81 bb [2] cf b7 [2] c3 bd [2] d4 b6 [2] cf f8 [2] f2 }

  condition:
    any of them
}