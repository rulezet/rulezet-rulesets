rule TTP_XOR_MULT_DOSStub_87d4 {
  strings:
    $key_87d4 = { d3 bc [2] a7 a4 [2] e0 a6 [2] a7 b7 [2] e9 bb [2] e5 b1 [2] f2 ba [2] e9 f4 [2] d4 }

  condition:
    any of them
}