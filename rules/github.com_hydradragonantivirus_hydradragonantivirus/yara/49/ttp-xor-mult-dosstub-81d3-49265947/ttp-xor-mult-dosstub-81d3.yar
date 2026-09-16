rule TTP_XOR_MULT_DOSStub_81d3 {
  strings:
    $key_81d3 = { d5 bb [2] a1 a3 [2] e6 a1 [2] a1 b0 [2] ef bc [2] e3 b6 [2] f4 bd [2] ef f3 [2] d2 }

  condition:
    any of them
}