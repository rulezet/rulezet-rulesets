rule TTP_XOR_MULT_DOSStub_84d3 {
  strings:
    $key_84d3 = { d0 bb [2] a4 a3 [2] e3 a1 [2] a4 b0 [2] ea bc [2] e6 b6 [2] f1 bd [2] ea f3 [2] d7 }

  condition:
    any of them
}