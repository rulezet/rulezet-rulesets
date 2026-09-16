rule TTP_XOR_MULT_DOSStub_87d2 {
  strings:
    $key_87d2 = { d3 ba [2] a7 a2 [2] e0 a0 [2] a7 b1 [2] e9 bd [2] e5 b7 [2] f2 bc [2] e9 f2 [2] d4 }

  condition:
    any of them
}