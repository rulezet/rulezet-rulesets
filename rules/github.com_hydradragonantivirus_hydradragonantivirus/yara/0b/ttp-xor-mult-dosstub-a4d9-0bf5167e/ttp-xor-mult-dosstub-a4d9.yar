rule TTP_XOR_MULT_DOSStub_a4d9 {
  strings:
    $key_a4d9 = { f0 b1 [2] 84 a9 [2] c3 ab [2] 84 ba [2] ca b6 [2] c6 bc [2] d1 b7 [2] ca f9 [2] f7 }

  condition:
    any of them
}