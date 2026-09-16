rule TTP_XOR_MULT_DOSStub_a4c1 {
  strings:
    $key_a4c1 = { f0 a9 [2] 84 b1 [2] c3 b3 [2] 84 a2 [2] ca ae [2] c6 a4 [2] d1 af [2] ca e1 [2] f7 }

  condition:
    any of them
}