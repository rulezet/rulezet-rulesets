rule TTP_XOR_MULT_DOSStub_80d5 {
  strings:
    $key_80d5 = { d4 bd [2] a0 a5 [2] e7 a7 [2] a0 b6 [2] ee ba [2] e2 b0 [2] f5 bb [2] ee f5 [2] d3 }

  condition:
    any of them
}