rule TTP_XOR_MULT_DOSStub_a7d8 {
  strings:
    $key_a7d8 = { f3 b0 [2] 87 a8 [2] c0 aa [2] 87 bb [2] c9 b7 [2] c5 bd [2] d2 b6 [2] c9 f8 [2] f4 }

  condition:
    any of them
}