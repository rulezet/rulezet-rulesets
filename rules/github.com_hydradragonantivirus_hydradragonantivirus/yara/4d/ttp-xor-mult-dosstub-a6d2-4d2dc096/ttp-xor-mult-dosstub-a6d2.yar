rule TTP_XOR_MULT_DOSStub_a6d2 {
  strings:
    $key_a6d2 = { f2 ba [2] 86 a2 [2] c1 a0 [2] 86 b1 [2] c8 bd [2] c4 b7 [2] d3 bc [2] c8 f2 [2] f5 }

  condition:
    any of them
}