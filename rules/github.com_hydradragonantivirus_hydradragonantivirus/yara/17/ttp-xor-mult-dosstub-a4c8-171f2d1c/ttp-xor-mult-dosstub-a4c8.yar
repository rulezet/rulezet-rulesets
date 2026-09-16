rule TTP_XOR_MULT_DOSStub_a4c8 {
  strings:
    $key_a4c8 = { f0 a0 [2] 84 b8 [2] c3 ba [2] 84 ab [2] ca a7 [2] c6 ad [2] d1 a6 [2] ca e8 [2] f7 }

  condition:
    any of them
}