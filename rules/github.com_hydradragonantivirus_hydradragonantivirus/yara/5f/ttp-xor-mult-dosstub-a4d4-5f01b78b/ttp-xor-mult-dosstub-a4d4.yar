rule TTP_XOR_MULT_DOSStub_a4d4 {
  strings:
    $key_a4d4 = { f0 bc [2] 84 a4 [2] c3 a6 [2] 84 b7 [2] ca bb [2] c6 b1 [2] d1 ba [2] ca f4 [2] f7 }

  condition:
    any of them
}