rule TTP_XOR_MULT_DOSStub_a1d5 {
  strings:
    $key_a1d5 = { f5 bd [2] 81 a5 [2] c6 a7 [2] 81 b6 [2] cf ba [2] c3 b0 [2] d4 bb [2] cf f5 [2] f2 }

  condition:
    any of them
}