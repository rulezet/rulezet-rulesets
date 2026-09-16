rule TTP_XOR_MULT_DOSStub_a1d3 {
  strings:
    $key_a1d3 = { f5 bb [2] 81 a3 [2] c6 a1 [2] 81 b0 [2] cf bc [2] c3 b6 [2] d4 bd [2] cf f3 [2] f2 }

  condition:
    any of them
}