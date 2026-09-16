rule TTP_XOR_MULT_DOSStub_a4c3 {
  strings:
    $key_a4c3 = { f0 ab [2] 84 b3 [2] c3 b1 [2] 84 a0 [2] ca ac [2] c6 a6 [2] d1 ad [2] ca e3 [2] f7 }

  condition:
    any of them
}