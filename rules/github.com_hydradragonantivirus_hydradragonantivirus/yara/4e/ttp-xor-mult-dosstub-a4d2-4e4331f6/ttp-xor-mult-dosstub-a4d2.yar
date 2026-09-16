rule TTP_XOR_MULT_DOSStub_a4d2 {
  strings:
    $key_a4d2 = { f0 ba [2] 84 a2 [2] c3 a0 [2] 84 b1 [2] ca bd [2] c6 b7 [2] d1 bc [2] ca f2 [2] f7 }

  condition:
    any of them
}